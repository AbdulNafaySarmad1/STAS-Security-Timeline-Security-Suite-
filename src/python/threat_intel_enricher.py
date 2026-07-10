import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import aiohttp


LOGGER = logging.getLogger(__name__)


@dataclass
class ThreatIntelSourceResult:
    name: str
    verdict: str
    malware_family: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    last_seen: Optional[str] = None
    confidence: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIntelResult:
    ioc_value: str
    ioc_type: str
    sources: List[ThreatIntelSourceResult]
    aggregate_verdict: str
    aggregate_score: int


class AsyncRateLimiter:
    def __init__(self, min_interval_seconds: float):
        self.min_interval_seconds = min_interval_seconds
        self._lock = asyncio.Lock()
        self._last_call = 0.0

    async def wait(self) -> None:
        async with self._lock:
            elapsed = time.monotonic() - self._last_call
            wait_for = self.min_interval_seconds - elapsed
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last_call = time.monotonic()


class ThreatIntelEnricher:
    DEFAULT_TTL_SECONDS = 24 * 60 * 60

    def __init__(
        self,
        config_path: Optional[str] = None,
        cache_path: Optional[str] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        timeout_seconds: int = 30,
        max_retries: int = 3,
    ):
        here = os.path.dirname(os.path.abspath(__file__))
        self.config_path = config_path or os.path.abspath(os.path.join(here, "../../data/threat_intel_config.json"))
        self.cache_path = cache_path or os.path.abspath(os.path.join(here, "../../data/threat_intel_cache.db"))
        self.ttl_seconds = ttl_seconds
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.config = self._load_config(self.config_path)
        self.rate_limiters = self._build_rate_limiters()
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        self._init_cache()

    async def enrich_iocs(self, iocs: Iterable[Dict[str, str] | Tuple[str, str]]) -> List[ThreatIntelResult]:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
            headers={"User-Agent": "STAS-ThreatIntelEnricher/1.0"},
        ) as session:
            tasks = []
            for item in iocs:
                if isinstance(item, dict):
                    value = str(item.get("value") or item.get("ioc_value") or "")
                    ioc_type = str(item.get("type") or item.get("ioc_type") or self.infer_ioc_type(value))
                else:
                    value, ioc_type = item
                if value:
                    tasks.append(self.enrich_ioc(value, ioc_type, session))
            return await asyncio.gather(*tasks)

    async def enrich_ioc(
        self,
        ioc_value: str,
        ioc_type: Optional[str] = None,
        session: Optional[aiohttp.ClientSession] = None,
    ) -> ThreatIntelResult:
        normalized_type = self.normalize_ioc_type(ioc_type or self.infer_ioc_type(ioc_value))
        cached = self._get_cached_result(ioc_value, normalized_type)
        if cached is not None:
            return cached

        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                headers={"User-Agent": "STAS-ThreatIntelEnricher/1.0"},
            )

        assert session is not None
        try:
            source_tasks = self._source_tasks(session, ioc_value, normalized_type)
            nested_results = await asyncio.gather(*source_tasks, return_exceptions=True)
        finally:
            if own_session:
                await session.close()

        sources: List[ThreatIntelSourceResult] = []
        for item in nested_results:
            if isinstance(item, Exception):
                LOGGER.warning("Threat intel source failed for %s: %s", ioc_value, item)
                continue
            if item:
                sources.extend(item)

        aggregate_verdict, aggregate_score = self._aggregate(sources)
        result = ThreatIntelResult(
            ioc_value=ioc_value,
            ioc_type=normalized_type,
            sources=sources,
            aggregate_verdict=aggregate_verdict,
            aggregate_score=aggregate_score,
        )
        self._set_cached_result(result)
        return result

    def export_json(self, results: List[ThreatIntelResult], path: Optional[str] = None) -> str:
        payload = json.dumps([self.result_to_dict(result) for result in results], indent=2)
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(payload)
        return payload

    def export_stix(self, results: List[ThreatIntelResult], path: Optional[str] = None) -> Dict[str, Any]:
        objects = []
        for result in results:
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": self._stix_id(result),
                    "created": self._now_stix(),
                    "modified": self._now_stix(),
                    "name": f"{result.ioc_type}: {result.ioc_value}",
                    "description": f"STAS aggregate verdict: {result.aggregate_verdict} ({result.aggregate_score}/100)",
                    "pattern_type": "stix",
                    "pattern": self._stix_pattern(result),
                    "valid_from": self._now_stix(),
                    "confidence": result.aggregate_score,
                    "labels": ["malicious-activity" if result.aggregate_score >= 60 else "suspicious-activity"],
                    "external_references": [
                        {
                            "source_name": source.name,
                            "description": source.verdict,
                        }
                        for source in result.sources
                    ],
                    "x_stas_sources": [asdict(source) for source in result.sources],
                }
            )
        bundle = {
            "type": "bundle",
            "id": "bundle--" + self._uuidish("stas-threat-intel-bundle"),
            "spec_version": "2.1",
            "objects": objects,
        }
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(bundle, handle, indent=2)
        return bundle

    def export_misp(self, results: List[ThreatIntelResult], path: Optional[str] = None) -> Dict[str, Any]:
        attributes = []
        for result in results:
            attributes.append(
                {
                    "type": self._misp_type(result.ioc_type),
                    "category": self._misp_category(result.ioc_type),
                    "value": result.ioc_value,
                    "to_ids": result.aggregate_score >= 60,
                    "comment": f"STAS verdict={result.aggregate_verdict}, score={result.aggregate_score}",
                    "Tag": [
                        {"name": f"stas:verdict=\"{result.aggregate_verdict}\""},
                        {"name": f"stas:score=\"{result.aggregate_score}\""},
                    ],
                }
            )
        event = {
            "Event": {
                "info": "STAS enriched malware analysis IOCs",
                "date": datetime.now(timezone.utc).date().isoformat(),
                "distribution": "0",
                "threat_level_id": "2",
                "analysis": "1",
                "Attribute": attributes,
            }
        }
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(event, handle, indent=2)
        return event

    async def _query_virustotal(
        self,
        session: aiohttp.ClientSession,
        ioc_value: str,
        ioc_type: str,
    ) -> List[ThreatIntelSourceResult]:
        api_key = self._api_key("virustotal")
        if not api_key:
            return []

        endpoint = None
        if ioc_type in {"SHA256", "SHA1", "MD5", "HASH"}:
            endpoint = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        elif ioc_type in {"IP", "IPV4", "IPV6"}:
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
        elif ioc_type in {"DOMAIN", "C2_DGA_DOMAIN", "ONION"}:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
        if not endpoint:
            return []

        data = await self._request_json(
            session,
            "VirusTotal",
            "GET",
            endpoint,
            headers={"x-apikey": api_key},
        )
        if not data:
            return []

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(value or 0) for value in stats.values()) or 1
        score = min(100, int(((malicious * 1.0 + suspicious * 0.5) / total) * 100))
        verdict = self._verdict_from_score(score)
        tags = list(attrs.get("tags") or [])
        last_seen = self._epoch_to_iso(attrs.get("last_analysis_date") or attrs.get("last_modification_date"))

        return [
            ThreatIntelSourceResult(
                name="VirusTotal",
                verdict=verdict,
                tags=tags,
                last_seen=last_seen,
                confidence=score,
                raw=self._compact_raw(data),
            )
        ]

    async def _query_malwarebazaar(
        self,
        session: aiohttp.ClientSession,
        ioc_value: str,
        ioc_type: str,
    ) -> List[ThreatIntelSourceResult]:
        if ioc_type not in {"SHA256", "SHA1", "MD5", "HASH"}:
            return []
        data = await self._request_json(
            session,
            "MalwareBazaar",
            "POST",
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": ioc_value},
        )
        if not data or data.get("query_status") not in {"ok", "hash_not_found"}:
            return []
        if data.get("query_status") == "hash_not_found":
            return [ThreatIntelSourceResult(name="MalwareBazaar", verdict="clean", confidence=10, raw=data)]

        entries = data.get("data") or []
        results = []
        for entry in entries:
            tags = list(entry.get("tags") or [])
            family = entry.get("signature") or entry.get("malware_family")
            confidence = 90 if family or tags else 70
            results.append(
                ThreatIntelSourceResult(
                    name="MalwareBazaar",
                    verdict="malicious",
                    malware_family=family,
                    tags=tags,
                    last_seen=entry.get("last_seen"),
                    confidence=confidence,
                    raw=self._compact_raw(entry),
                )
            )
        return results

    async def _query_urlhaus(
        self,
        session: aiohttp.ClientSession,
        ioc_value: str,
        ioc_type: str,
    ) -> List[ThreatIntelSourceResult]:
        if ioc_type in {"URL"}:
            payload = {"url": ioc_value}
            endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        elif ioc_type in {"DOMAIN", "C2_DGA_DOMAIN", "ONION"}:
            payload = {"host": ioc_value}
            endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
        else:
            return []

        data = await self._request_json(
            session,
            "URLhaus",
            "POST",
            endpoint,
            data=payload,
        )
        if not data:
            return []
        status = data.get("query_status")
        if status in {"no_results", "invalid_url"}:
            return [ThreatIntelSourceResult(name="URLhaus", verdict="clean", confidence=10, raw=data)]
        if status not in {"ok"}:
            return []

        tags = list(data.get("tags") or [])
        family = data.get("threat") or data.get("malware_family")
        return [
            ThreatIntelSourceResult(
                name="URLhaus",
                verdict="malicious" if data.get("url_status") != "offline" else "suspicious",
                malware_family=family,
                tags=tags,
                last_seen=data.get("last_online") or data.get("date_added"),
                confidence=85,
                raw=self._compact_raw(data),
            )
        ]

    async def _query_abuseipdb(
        self,
        session: aiohttp.ClientSession,
        ioc_value: str,
        ioc_type: str,
    ) -> List[ThreatIntelSourceResult]:
        api_key = self._api_key("abuseipdb")
        if not api_key or ioc_type not in {"IP", "IPV4", "IPV6"}:
            return []
        data = await self._request_json(
            session,
            "AbuseIPDB",
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ioc_value, "maxAgeInDays": "90", "verbose": "true"},
        )
        if not data:
            return []
        attrs = data.get("data", {})
        score = int(attrs.get("abuseConfidenceScore") or 0)
        tags = []
        if attrs.get("usageType"):
            tags.append(str(attrs["usageType"]))
        if attrs.get("domain"):
            tags.append(str(attrs["domain"]))
        return [
            ThreatIntelSourceResult(
                name="AbuseIPDB",
                verdict=self._verdict_from_score(score),
                tags=tags,
                last_seen=attrs.get("lastReportedAt"),
                confidence=score,
                raw=self._compact_raw(data),
            )
        ]

    async def _query_threatfox(
        self,
        session: aiohttp.ClientSession,
        ioc_value: str,
        ioc_type: str,
    ) -> List[ThreatIntelSourceResult]:
        data = await self._request_json(
            session,
            "ThreatFox",
            "POST",
            "https://threatfox-api.abuse.ch/api/v1/",
            json_payload={"query": "search_ioc", "search_term": ioc_value},
        )
        if not data:
            return []
        status = data.get("query_status")
        if status in {"no_result", "no_results"}:
            return [ThreatIntelSourceResult(name="ThreatFox", verdict="clean", confidence=10, raw=data)]
        if status != "ok":
            return []

        results = []
        for entry in data.get("data") or []:
            tags = list(entry.get("tags") or [])
            family = entry.get("malware_printable") or entry.get("malware") or entry.get("malware_family")
            confidence = int(entry.get("confidence_level") or 80)
            results.append(
                ThreatIntelSourceResult(
                    name="ThreatFox",
                    verdict="malicious",
                    malware_family=family,
                    tags=tags,
                    last_seen=entry.get("last_seen") or entry.get("first_seen"),
                    confidence=min(100, max(0, confidence)),
                    raw=self._compact_raw(entry),
                )
            )
        return results

    def _source_tasks(
        self,
        session: aiohttp.ClientSession,
        ioc_value: str,
        ioc_type: str,
    ) -> List[asyncio.Task]:
        tasks = [
            asyncio.create_task(self._query_virustotal(session, ioc_value, ioc_type)),
            asyncio.create_task(self._query_malwarebazaar(session, ioc_value, ioc_type)),
            asyncio.create_task(self._query_urlhaus(session, ioc_value, ioc_type)),
            asyncio.create_task(self._query_abuseipdb(session, ioc_value, ioc_type)),
            asyncio.create_task(self._query_threatfox(session, ioc_value, ioc_type)),
        ]
        return tasks

    async def _request_json(
        self,
        session: aiohttp.ClientSession,
        source_name: str,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json_payload: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        limiter = self.rate_limiters[source_name]
        for attempt in range(1, self.max_retries + 1):
            await limiter.wait()
            try:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_payload,
                ) as response:
                    if response.status == 404:
                        return {}
                    if response.status in {429, 500, 502, 503, 504}:
                        retry_after = response.headers.get("Retry-After")
                        delay = float(retry_after) if retry_after and retry_after.isdigit() else min(2 ** attempt, 30)
                        LOGGER.warning("%s returned %s; retrying in %.1fs", source_name, response.status, delay)
                        await asyncio.sleep(delay)
                        continue
                    if response.status >= 400:
                        body = await response.text()
                        LOGGER.warning("%s request failed HTTP %s: %s", source_name, response.status, body[:300])
                        return None
                    return await response.json(content_type=None)
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                if attempt >= self.max_retries:
                    LOGGER.warning("%s request failed after %s attempts: %s", source_name, attempt, exc)
                    return None
                await asyncio.sleep(min(2 ** attempt, 20))
        return None

    def _build_rate_limiters(self) -> Dict[str, AsyncRateLimiter]:
        limits = self.config.get("rate_limits", {})
        defaults = {
            "VirusTotal": 16.0,
            "MalwareBazaar": 1.0,
            "URLhaus": 1.0,
            "AbuseIPDB": 2.0,
            "ThreatFox": 1.0,
        }
        return {
            name: AsyncRateLimiter(float(limits.get(name, interval)))
            for name, interval in defaults.items()
        }

    def _load_config(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            return {"api_keys": {}, "rate_limits": {}}
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _api_key(self, provider: str) -> Optional[str]:
        env_names = {
            "virustotal": "VT_API_KEY",
            "abuseipdb": "ABUSEIPDB_API_KEY",
        }
        if env_names.get(provider) and os.environ.get(env_names[provider]):
            return os.environ[env_names[provider]]
        return self.config.get("api_keys", {}).get(provider)

    def _init_cache(self) -> None:
        conn = sqlite3.connect(self.cache_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS intel_cache(
                ioc_value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(ioc_value, ioc_type)
            )
            """
        )
        conn.commit()
        conn.close()

    def _get_cached_result(self, ioc_value: str, ioc_type: str) -> Optional[ThreatIntelResult]:
        conn = sqlite3.connect(self.cache_path)
        row = conn.execute(
            "SELECT result_json, created_at FROM intel_cache WHERE ioc_value=? AND ioc_type=?",
            (ioc_value, ioc_type),
        ).fetchone()
        conn.close()
        if not row:
            return None
        result_json, created_at = row
        if int(time.time()) - int(created_at) > self.ttl_seconds:
            return None
        return self.result_from_dict(json.loads(result_json))

    def _set_cached_result(self, result: ThreatIntelResult) -> None:
        conn = sqlite3.connect(self.cache_path)
        conn.execute(
            """
            INSERT OR REPLACE INTO intel_cache(ioc_value, ioc_type, result_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                result.ioc_value,
                result.ioc_type,
                json.dumps(self.result_to_dict(result)),
                int(time.time()),
            ),
        )
        conn.commit()
        conn.close()

    def _aggregate(self, sources: List[ThreatIntelSourceResult]) -> Tuple[str, int]:
        if not sources:
            return "unknown", 0
        score = 0.0
        weight = 0.0
        for source in sources:
            source_weight = 1.2 if source.name in {"VirusTotal", "MalwareBazaar", "ThreatFox"} else 1.0
            if source.verdict == "malicious":
                score += source.confidence * source_weight
            elif source.verdict == "suspicious":
                score += max(35, source.confidence) * 0.7 * source_weight
            elif source.verdict == "clean":
                score += min(source.confidence, 15) * 0.15
            weight += source_weight
        aggregate_score = int(max(0, min(100, round(score / max(weight, 1.0)))))
        return self._verdict_from_score(aggregate_score), aggregate_score

    def _verdict_from_score(self, score: int) -> str:
        if score >= 70:
            return "malicious"
        if score >= 30:
            return "suspicious"
        if score > 0:
            return "clean"
        return "unknown"

    def normalize_ioc_type(self, ioc_type: str) -> str:
        upper = (ioc_type or "").upper()
        mapping = {
            "IPV4": "IPV4",
            "IPV6": "IPV6",
            "IP": "IP",
            "DOMAIN": "DOMAIN",
            "C2_DGA_DOMAIN": "DOMAIN",
            "ONION": "DOMAIN",
            "URL": "URL",
            "SHA256": "SHA256",
            "SHA1": "SHA1",
            "MD5": "MD5",
            "HASH": "HASH",
        }
        return mapping.get(upper, upper or "UNKNOWN")

    def infer_ioc_type(self, value: str) -> str:
        lowered = value.lower()
        if lowered.startswith(("http://", "https://", "ftp://")):
            return "URL"
        if self._is_hash(value, 64):
            return "SHA256"
        if self._is_hash(value, 40):
            return "SHA1"
        if self._is_hash(value, 32):
            return "MD5"
        if ":" in value and all(part == "" or self._is_hash(part, len(part), allow_lengths=True) for part in value.split(":")):
            return "IPV6"
        if self._looks_like_ipv4(value):
            return "IPV4"
        if "." in value:
            return "DOMAIN"
        return "UNKNOWN"

    def result_to_dict(self, result: ThreatIntelResult) -> Dict[str, Any]:
        return {
            "ioc_value": result.ioc_value,
            "ioc_type": result.ioc_type,
            "sources": [asdict(source) for source in result.sources],
            "aggregate_verdict": result.aggregate_verdict,
            "aggregate_score": result.aggregate_score,
        }

    def result_from_dict(self, data: Dict[str, Any]) -> ThreatIntelResult:
        return ThreatIntelResult(
            ioc_value=data["ioc_value"],
            ioc_type=data["ioc_type"],
            sources=[ThreatIntelSourceResult(**source) for source in data.get("sources", [])],
            aggregate_verdict=data.get("aggregate_verdict", "unknown"),
            aggregate_score=int(data.get("aggregate_score", 0)),
        )

    def _compact_raw(self, data: Dict[str, Any]) -> Dict[str, Any]:
        text = json.dumps(data)
        if len(text) <= 6000:
            return data
        return {"truncated": True, "preview": text[:6000]}

    def _epoch_to_iso(self, value: Any) -> Optional[str]:
        try:
            if value is None:
                return None
            return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            return None

    def _stix_pattern(self, result: ThreatIntelResult) -> str:
        field = {
            "IPV4": "ipv4-addr:value",
            "IPV6": "ipv6-addr:value",
            "IP": "ipv4-addr:value",
            "DOMAIN": "domain-name:value",
            "URL": "url:value",
            "SHA256": "file:hashes.'SHA-256'",
            "SHA1": "file:hashes.'SHA-1'",
            "MD5": "file:hashes.MD5",
            "HASH": "file:hashes.'SHA-256'",
        }.get(result.ioc_type, "artifact:payload_bin")
        escaped = result.ioc_value.replace("\\", "\\\\").replace("'", "\\'")
        return f"[{field} = '{escaped}']"

    def _stix_id(self, result: ThreatIntelResult) -> str:
        return "indicator--" + self._uuidish(f"{result.ioc_type}:{result.ioc_value}")

    def _uuidish(self, value: str) -> str:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return f"{digest[0:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}"

    def _now_stix(self) -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _misp_type(self, ioc_type: str) -> str:
        return {
            "IPV4": "ip-dst",
            "IPV6": "ip-dst",
            "IP": "ip-dst",
            "DOMAIN": "domain",
            "URL": "url",
            "SHA256": "sha256",
            "SHA1": "sha1",
            "MD5": "md5",
            "HASH": "sha256",
        }.get(ioc_type, "text")

    def _misp_category(self, ioc_type: str) -> str:
        if ioc_type in {"SHA256", "SHA1", "MD5", "HASH"}:
            return "Payload delivery"
        if ioc_type in {"IP", "IPV4", "IPV6", "DOMAIN", "URL"}:
            return "Network activity"
        return "External analysis"

    def _is_hash(self, value: str, length: int, allow_lengths: bool = False) -> bool:
        if not allow_lengths and len(value) != length:
            return False
        if allow_lengths and not (1 <= len(value) <= 4):
            return False
        return all(ch in "0123456789abcdefABCDEF" for ch in value)

    def _looks_like_ipv4(self, value: str) -> bool:
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


async def _demo() -> None:
    enricher = ThreatIntelEnricher(cache_path="/tmp/stas_threat_intel_cache.db")
    results = await enricher.enrich_iocs(
        [
            {"value": "8.8.8.8", "type": "IPV4"},
            {"value": "example.com", "type": "DOMAIN"},
        ]
    )
    print(enricher.export_json(results))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_demo())
