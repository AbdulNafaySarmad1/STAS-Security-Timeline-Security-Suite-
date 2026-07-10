import asyncio
import json
import logging
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp


LOGGER = logging.getLogger(__name__)


@dataclass
class ReportOutput:
    executive_summary: str
    technical_analysis: str
    analyst_notes: str
    ioc_summary: str
    markdown: str
    model: str
    generated_at: str
    raw_model_response: str
    parsed: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class AIAnalystNarrator:
    DEFAULT_MODEL = "claude-sonnet-4-6"
    ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
    ANTHROPIC_VERSION = "2023-06-01"

    def __init__(
        self,
        config_path: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: int = 90,
        max_retries: int = 3,
        max_tokens: int = 5000,
    ):
        here = os.path.dirname(os.path.abspath(__file__))
        self.config_path = config_path or os.path.abspath(os.path.join(here, "../../data/ai_analyst_config.json"))
        self.config = self._load_config(self.config_path)
        self.model = model or self.config.get("model") or self.DEFAULT_MODEL
        self.timeout_seconds = int(self.config.get("timeout_seconds", timeout_seconds))
        self.max_retries = int(self.config.get("max_retries", max_retries))
        self.max_tokens = int(self.config.get("max_tokens", max_tokens))

    def generate_report(self, analysis_json: Dict[str, Any]) -> ReportOutput:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.generate_report_async(analysis_json))

        result: Dict[str, Any] = {}
        error: Dict[str, BaseException] = {}

        def runner() -> None:
            try:
                result["value"] = asyncio.run(self.generate_report_async(analysis_json))
            except BaseException as exc:
                error["value"] = exc

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        thread.join()
        if error:
            raise error["value"]
        return result["value"]

    async def generate_report_async(self, analysis_json: Dict[str, Any]) -> ReportOutput:
        self._validate_analysis(analysis_json)
        api_key = self._api_key()
        if not api_key:
            raise RuntimeError(
                "Anthropic API key not configured. Set ANTHROPIC_API_KEY or create data/ai_analyst_config.json."
            )

        compact_analysis = self._compact_analysis(analysis_json)
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0.2,
            "system": self.system_prompt(),
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": self.user_prompt(compact_analysis),
                        }
                    ],
                }
            ],
        }

        raw_text = await self._call_claude(payload, api_key)
        parsed = self.parse_model_output(raw_text)
        return self._build_report_output(parsed, raw_text)

    def system_prompt(self) -> str:
        return (
            "You are a senior malware reverse engineer and threat intelligence analyst writing for STAS, "
            "a malware analysis platform. Your job is to transform structured malware analysis JSON into "
            "analyst-grade reporting.\n\n"
            "Persona and language rules:\n"
            "- Be precise, sober, and evidence-driven.\n"
            "- Use confidence-based language: 'with high confidence', 'likely', 'possibly', "
            "'insufficient evidence', and 'not observed'.\n"
            "- Never invent IOCs, ATT&CK techniques, malware families, timestamps, campaign names, or tools.\n"
            "- If evidence is missing, explicitly state the gap and what collection would close it.\n"
            "- Distinguish observed behavior from inferred behavior.\n"
            "- Avoid operational instructions that would improve malware. Keep recommendations defensive.\n\n"
            "Output contract:\n"
            "Return exactly one valid JSON object and no surrounding prose. The JSON object must contain "
            "these string fields: executive_summary, technical_analysis, analyst_notes, ioc_summary, markdown. "
            "The markdown field must contain the same four sections formatted with Markdown headings."
        )

    def user_prompt(self, analysis_json: Dict[str, Any]) -> str:
        return (
            "Generate the following four report sections from the analysis JSON.\n\n"
            "1. EXECUTIVE SUMMARY: 3-4 non-technical sentences covering what the malware likely does, "
            "business risk level, and recommended immediate action.\n"
            "2. TECHNICAL ANALYSIS: Detailed analyst-grade behavior narrative with ATT&CK references, "
            "confidence levels, possible malware family reasoning, and kill-chain stage assessment.\n"
            "3. ANALYST NOTES: Unusual/notable findings, analysis gaps, follow-up steps, and similar campaigns "
            "only when supported by evidence.\n"
            "4. IOC SUMMARY: Ingestion-ready IOC list and defensive detection recommendations, including "
            "YARA and Sigma rule hints.\n\n"
            "Use only the evidence in this JSON:\n"
            f"{json.dumps(analysis_json, indent=2, sort_keys=True)}"
        )

    def parse_model_output(self, raw_text: str) -> Dict[str, Any]:
        candidates = [raw_text]
        fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, flags=re.DOTALL)
        candidates = fenced + candidates

        first_brace = raw_text.find("{")
        last_brace = raw_text.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            candidates.insert(0, raw_text[first_brace : last_brace + 1])

        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
                return self._normalize_parsed_output(parsed)
            except json.JSONDecodeError:
                continue

        LOGGER.warning("Claude response was not valid JSON; falling back to section parser")
        return self._parse_markdown_sections(raw_text)

    async def _call_claude(self, payload: Dict[str, Any], api_key: str) -> str:
        headers = {
            "x-api-key": api_key,
            "anthropic-version": self.ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for attempt in range(1, self.max_retries + 1):
                try:
                    async with session.post(self.ANTHROPIC_URL, headers=headers, json=payload) as response:
                        body = await response.text()
                        if response.status in {429, 500, 502, 503, 504}:
                            delay = self._retry_delay(response.headers.get("Retry-After"), attempt)
                            LOGGER.warning("Claude API returned %s; retrying in %.1fs", response.status, delay)
                            await asyncio.sleep(delay)
                            continue
                        if response.status >= 400:
                            raise RuntimeError(f"Claude API request failed HTTP {response.status}: {body[:500]}")
                        data = json.loads(body)
                        return self._extract_text(data)
                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    if attempt >= self.max_retries:
                        raise RuntimeError(f"Claude API request failed after {attempt} attempts: {exc}") from exc
                    await asyncio.sleep(min(2**attempt, 20))

        raise RuntimeError("Claude API request failed without a response")

    def _extract_text(self, response_json: Dict[str, Any]) -> str:
        parts: List[str] = []
        for item in response_json.get("content", []):
            if item.get("type") == "text":
                parts.append(item.get("text", ""))
        text = "\n".join(part for part in parts if part).strip()
        if not text:
            raise RuntimeError("Claude API response did not contain text content")
        return text

    def _normalize_parsed_output(self, parsed: Dict[str, Any]) -> Dict[str, str]:
        required = ["executive_summary", "technical_analysis", "analyst_notes", "ioc_summary"]
        normalized: Dict[str, str] = {}
        for key in required:
            value = parsed.get(key, "")
            normalized[key] = value if isinstance(value, str) else json.dumps(value, indent=2)

        markdown = parsed.get("markdown")
        if not isinstance(markdown, str) or not markdown.strip():
            markdown = self._compose_markdown(normalized)
        normalized["markdown"] = markdown
        return normalized

    def _parse_markdown_sections(self, text: str) -> Dict[str, str]:
        section_map = {
            "executive_summary": r"executive summary",
            "technical_analysis": r"technical analysis",
            "analyst_notes": r"analyst notes",
            "ioc_summary": r"ioc summary",
        }
        parsed: Dict[str, str] = {}
        for key, heading in section_map.items():
            match = re.search(
                rf"(?is)(?:^|\n)#+\s*{heading}\s*\n(.*?)(?=\n#+\s*(?:executive summary|technical analysis|analyst notes|ioc summary)\b|\Z)",
                text,
            )
            parsed[key] = match.group(1).strip() if match else ""

        if not any(parsed.values()):
            parsed["technical_analysis"] = text.strip()
        parsed["markdown"] = self._compose_markdown(parsed)
        return parsed

    def _build_report_output(self, parsed: Dict[str, str], raw_text: str) -> ReportOutput:
        generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        return ReportOutput(
            executive_summary=parsed.get("executive_summary", "").strip(),
            technical_analysis=parsed.get("technical_analysis", "").strip(),
            analyst_notes=parsed.get("analyst_notes", "").strip(),
            ioc_summary=parsed.get("ioc_summary", "").strip(),
            markdown=parsed.get("markdown", self._compose_markdown(parsed)).strip(),
            model=self.model,
            generated_at=generated_at,
            raw_model_response=raw_text,
            parsed=parsed,
        )

    def _compose_markdown(self, sections: Dict[str, str]) -> str:
        return "\n\n".join(
            [
                "# Executive Summary\n" + sections.get("executive_summary", "").strip(),
                "# Technical Analysis\n" + sections.get("technical_analysis", "").strip(),
                "# Analyst Notes\n" + sections.get("analyst_notes", "").strip(),
                "# IOC Summary\n" + sections.get("ioc_summary", "").strip(),
            ]
        )

    def _compact_analysis(self, analysis_json: Dict[str, Any]) -> Dict[str, Any]:
        compact = json.loads(json.dumps(analysis_json, default=str))
        events = compact.get("dynamic", {}).get("events")
        if isinstance(events, list) and len(events) > 150:
            compact["dynamic"]["events"] = events[:75] + [
                {"note": f"{len(events) - 150} middle events omitted for prompt size"}
            ] + events[-75:]

        for event in compact.get("dynamic", {}).get("events", []) if isinstance(compact.get("dynamic", {}).get("events"), list) else []:
            raw = event.get("raw_data") if isinstance(event, dict) else None
            if isinstance(raw, str) and len(raw) > 1200:
                event["raw_data"] = raw[:1200] + "...[truncated]"
            elif isinstance(raw, dict):
                raw_text = json.dumps(raw, default=str)
                if len(raw_text) > 1200:
                    event["raw_data"] = {"truncated": True, "preview": raw_text[:1200]}
        return compact

    def _validate_analysis(self, analysis_json: Dict[str, Any]) -> None:
        if not isinstance(analysis_json, dict):
            raise TypeError("analysis_json must be a dictionary")
        for key in ["sample", "static", "dynamic", "attack_techniques", "iocs", "ml_prediction", "risk_scores"]:
            if key not in analysis_json:
                raise ValueError(f"analysis_json missing required key: {key}")

    def _api_key(self) -> Optional[str]:
        return os.environ.get("ANTHROPIC_API_KEY") or self.config.get("anthropic_api_key")

    def _load_config(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _retry_delay(self, retry_after: Optional[str], attempt: int) -> float:
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass
        return float(min(2**attempt, 30))
