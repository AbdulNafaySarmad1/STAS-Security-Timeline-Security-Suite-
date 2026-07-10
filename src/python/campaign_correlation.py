import json
import os
import sqlite3
import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx


SIGNAL_WEIGHTS = {
    "shared_c2": 10,
    "shared_mutex": 9,
    "shared_named_pipe": 9,
    "shared_code_similarity": 8,
    "shared_imphash": 7,
    "shared_signer": 6,
    "shared_attack_combo": 5,
    "similar_compile_timestamp": 4,
    "same_packer": 4,
    "same_family": 3,
    "same_archetype": 2,
    "overlapping_strings": 2,
}


@dataclass
class MalwareSample:
    sample_id: str
    name: str = ""
    sha256: str = ""
    md5: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    compile_timestamp: Optional[int] = None
    family: str = ""
    archetype: str = ""
    risk_score: int = 0
    imphash: str = ""
    packer: str = ""
    signer: str = ""
    fuzzy_hash: str = ""
    domains: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    mutexes: Set[str] = field(default_factory=set)
    named_pipes: Set[str] = field(default_factory=set)
    attack_techniques: Set[str] = field(default_factory=set)
    strings: Set[str] = field(default_factory=set)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CampaignProfile:
    campaign_id: str
    sample_ids: List[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    shared_infrastructure: Dict[str, List[str]]
    attack_techniques: List[str]
    confidence_score: int
    attribution_hints: List[str]
    families: Dict[str, int]
    archetypes: Dict[str, int]


class CampaignGraph:
    def __init__(self, db_path: str = "data/campaign_correlation.db", min_edge_weight: int = 6):
        self.db_path = db_path
        self.min_edge_weight = min_edge_weight
        self.graph = nx.Graph()
        self.samples: Dict[str, MalwareSample] = {}
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    def load_from_database(self) -> Dict[str, MalwareSample]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        samples = {}
        for row in conn.execute("SELECT * FROM samples"):
            sample = self._row_to_sample(row)
            samples[sample.sample_id] = sample
        conn.close()
        self.samples = samples
        return samples

    def upsert_sample(self, sample: MalwareSample | Dict[str, Any]) -> MalwareSample:
        parsed = sample if isinstance(sample, MalwareSample) else self.sample_from_analysis(sample)
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            INSERT OR REPLACE INTO samples(
                sample_id, name, sha256, md5, first_seen, last_seen, compile_timestamp,
                family, archetype, risk_score, imphash, packer, signer, fuzzy_hash, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                parsed.sample_id,
                parsed.name,
                parsed.sha256,
                parsed.md5,
                parsed.first_seen,
                parsed.last_seen,
                parsed.compile_timestamp,
                parsed.family,
                parsed.archetype,
                parsed.risk_score,
                parsed.imphash,
                parsed.packer,
                parsed.signer,
                parsed.fuzzy_hash,
                json.dumps(self._sample_to_json(parsed)),
            ),
        )
        conn.execute("DELETE FROM iocs WHERE sample_id=?", (parsed.sample_id,))
        for ioc_type, values in {
            "domain": parsed.domains,
            "ip": parsed.ips,
            "mutex": parsed.mutexes,
            "named_pipe": parsed.named_pipes,
            "attack_technique": parsed.attack_techniques,
            "string": parsed.strings,
        }.items():
            for value in values:
                conn.execute(
                    "INSERT OR IGNORE INTO iocs(sample_id, ioc_type, value) VALUES (?, ?, ?)",
                    (parsed.sample_id, ioc_type, value),
                )
        conn.commit()
        conn.close()
        self.samples[parsed.sample_id] = parsed
        return parsed

    def build_graph(self, samples: Optional[Iterable[MalwareSample | Dict[str, Any]]] = None) -> nx.Graph:
        if samples is not None:
            self.samples = {}
            for item in samples:
                sample = item if isinstance(item, MalwareSample) else self.sample_from_analysis(item)
                self.samples[sample.sample_id] = sample
        elif not self.samples:
            self.load_from_database()

        self.graph = nx.Graph()
        for sample in self.samples.values():
            self.graph.add_node(
                sample.sample_id,
                label=sample.name or sample.sample_id,
                family=sample.family,
                archetype=sample.archetype,
                risk_score=sample.risk_score,
                sha256=sample.sha256,
            )

        sample_list = list(self.samples.values())
        for index, left in enumerate(sample_list):
            for right in sample_list[index + 1 :]:
                score, signals = self.correlate_pair(left, right)
                if score >= self.min_edge_weight:
                    self.graph.add_edge(left.sample_id, right.sample_id, weight=score, signals=signals)

        self._persist_correlations()
        return self.graph

    def correlate_pair(self, left: MalwareSample, right: MalwareSample) -> Tuple[int, List[Dict[str, Any]]]:
        signals: List[Dict[str, Any]] = []

        shared_domains = sorted(left.domains & right.domains)
        shared_ips = sorted(left.ips & right.ips)
        if shared_domains or shared_ips:
            signals.append(self._signal("shared_c2", shared_domains + shared_ips))

        shared_mutexes = sorted(left.mutexes & right.mutexes)
        if shared_mutexes:
            signals.append(self._signal("shared_mutex", shared_mutexes))

        shared_pipes = sorted(left.named_pipes & right.named_pipes)
        if shared_pipes:
            signals.append(self._signal("shared_named_pipe", shared_pipes))

        code_similarity = self.fuzzy_similarity(left.fuzzy_hash, right.fuzzy_hash)
        if code_similarity >= 80:
            signals.append(self._signal("shared_code_similarity", [f"{code_similarity:.1f}%"]))

        if left.imphash and right.imphash and left.imphash.lower() == right.imphash.lower():
            signals.append(self._signal("shared_imphash", [left.imphash]))

        if left.signer and right.signer and left.signer.lower() == right.signer.lower():
            signals.append(self._signal("shared_signer", [left.signer]))

        shared_attack = sorted(left.attack_techniques & right.attack_techniques)
        if len(shared_attack) >= 2:
            signals.append(self._signal("shared_attack_combo", shared_attack))

        if self._compile_times_close(left.compile_timestamp, right.compile_timestamp):
            signals.append(self._signal("similar_compile_timestamp", [str(left.compile_timestamp), str(right.compile_timestamp)]))

        if left.packer and right.packer and left.packer.lower() == right.packer.lower():
            signals.append(self._signal("same_packer", [left.packer]))

        if left.family and right.family and left.family.lower() == right.family.lower():
            signals.append(self._signal("same_family", [left.family]))

        if left.archetype and right.archetype and left.archetype.lower() == right.archetype.lower():
            signals.append(self._signal("same_archetype", [left.archetype]))

        string_overlap = self._string_overlap(left.strings, right.strings)
        if len(string_overlap) >= 3:
            signals.append(self._signal("overlapping_strings", sorted(string_overlap)[:20]))

        total = sum(int(signal["weight"]) for signal in signals)
        return total, signals

    def detect_campaigns(self) -> List[CampaignProfile]:
        if self.graph.number_of_nodes() == 0:
            self.build_graph()

        communities = self._communities()
        profiles = []
        for community in communities:
            if not community:
                continue
            profile = self._build_campaign_profile(sorted(community))
            profiles.append(profile)
        profiles.sort(key=lambda item: (item.confidence_score, len(item.sample_ids)), reverse=True)
        self._persist_campaigns(profiles)
        return profiles

    def ioc_diff(self, sample_a: str, sample_b: str) -> Dict[str, Any]:
        left = self._get_sample(sample_a)
        right = self._get_sample(sample_b)
        categories = {
            "domains": (left.domains, right.domains),
            "ips": (left.ips, right.ips),
            "mutexes": (left.mutexes, right.mutexes),
            "named_pipes": (left.named_pipes, right.named_pipes),
            "attack_techniques": (left.attack_techniques, right.attack_techniques),
            "strings": (left.strings, right.strings),
        }
        diff = {}
        for name, (a_values, b_values) in categories.items():
            diff[name] = {
                "unique_to_a": sorted(a_values - b_values),
                "shared": sorted(a_values & b_values),
                "unique_to_b": sorted(b_values - a_values),
            }
        diff["new_c2_infrastructure"] = sorted((right.domains | right.ips) - (left.domains | left.ips))
        return {
            "sample_a": left.sample_id,
            "sample_b": right.sample_id,
            "diff": diff,
        }

    def export_html_graph(self, path: str, color_by: str = "campaign") -> str:
        campaigns = self.detect_campaigns()
        campaign_lookup = {sample_id: profile.campaign_id for profile in campaigns for sample_id in profile.sample_ids}
        if self._export_pyvis_graph(path, campaign_lookup, color_by):
            return path

        positions = nx.spring_layout(self.graph, seed=42, weight="weight") if self.graph.number_of_nodes() else {}
        nodes = []
        edges = []
        for node_id, attrs in self.graph.nodes(data=True):
            sample = self.samples[node_id]
            color_key = campaign_lookup.get(node_id) if color_by == "campaign" else getattr(sample, color_by, "")
            nodes.append(
                {
                    "id": node_id,
                    "label": attrs.get("label", node_id),
                    "x": float(positions.get(node_id, (0, 0))[0]),
                    "y": float(positions.get(node_id, (0, 0))[1]),
                    "color": self._color_for(color_key or sample.risk_score),
                    "details": self._sample_to_json(sample),
                }
            )
        for source, target, attrs in self.graph.edges(data=True):
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "weight": attrs.get("weight", 1),
                    "signals": attrs.get("signals", []),
                }
            )
        html = self._html_template(nodes, edges)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(html)
        return path

    def _export_pyvis_graph(self, path: str, campaign_lookup: Dict[str, str], color_by: str) -> bool:
        try:
            from pyvis.network import Network
        except ImportError:
            return False

        net = Network(height="850px", width="100%", bgcolor="#0D1117", font_color="#F8FAFC", directed=False)
        net.barnes_hut(gravity=-12000, central_gravity=0.2, spring_length=180, spring_strength=0.02)

        for node_id, attrs in self.graph.nodes(data=True):
            sample = self.samples[node_id]
            color_key = campaign_lookup.get(node_id) if color_by == "campaign" else getattr(sample, color_by, "")
            net.add_node(
                node_id,
                label=attrs.get("label", node_id),
                title=json.dumps(self._sample_to_json(sample), indent=2),
                color=self._color_for(color_key or sample.risk_score),
                value=max(10, sample.risk_score or 10),
            )

        for source, target, attrs in self.graph.edges(data=True):
            net.add_edge(
                source,
                target,
                value=max(1, int(attrs.get("weight", 1))),
                title=json.dumps(attrs.get("signals", []), indent=2),
            )

        net.write_html(path, notebook=False, open_browser=False)
        return True

    def export_stix(self, profiles: Optional[List[CampaignProfile]] = None) -> Dict[str, Any]:
        profiles = profiles or self.detect_campaigns()
        objects = []
        for profile in profiles:
            campaign_stix_id = "campaign--" + self._uuidish(profile.campaign_id)
            objects.append(
                {
                    "type": "campaign",
                    "spec_version": "2.1",
                    "id": campaign_stix_id,
                    "created": self._now(),
                    "modified": self._now(),
                    "name": profile.campaign_id,
                    "description": f"STAS correlated campaign containing {len(profile.sample_ids)} samples.",
                    "first_seen": profile.first_seen,
                    "last_seen": profile.last_seen,
                    "objective": "Unknown",
                    "x_stas_confidence_score": profile.confidence_score,
                    "x_stas_shared_infrastructure": profile.shared_infrastructure,
                    "x_stas_attack_techniques": profile.attack_techniques,
                    "x_stas_attribution_hints": profile.attribution_hints,
                }
            )
            for sample_id in profile.sample_ids:
                sample = self.samples[sample_id]
                malware_id = "malware--" + self._uuidish(sample.sample_id)
                objects.append(
                    {
                        "type": "malware",
                        "spec_version": "2.1",
                        "id": malware_id,
                        "created": self._now(),
                        "modified": self._now(),
                        "name": sample.family or sample.name or sample.sample_id,
                        "is_family": False,
                        "hashes": {"SHA-256": sample.sha256} if sample.sha256 else {},
                    }
                )
                objects.append(
                    {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": "relationship--" + self._uuidish(profile.campaign_id + sample.sample_id),
                        "created": self._now(),
                        "modified": self._now(),
                        "relationship_type": "uses",
                        "source_ref": campaign_stix_id,
                        "target_ref": malware_id,
                    }
                )
        return {
            "type": "bundle",
            "id": "bundle--" + self._uuidish("stas-campaign-correlation"),
            "spec_version": "2.1",
            "objects": objects,
        }

    def export_misp(self, profiles: Optional[List[CampaignProfile]] = None) -> Dict[str, Any]:
        profiles = profiles or self.detect_campaigns()
        events = []
        for profile in profiles:
            attributes = []
            for value in profile.shared_infrastructure.get("ips", []):
                attributes.append(self._misp_attribute("ip-dst", "Network activity", value, profile))
            for value in profile.shared_infrastructure.get("domains", []):
                attributes.append(self._misp_attribute("domain", "Network activity", value, profile))
            for value in profile.shared_infrastructure.get("mutexes", []):
                attributes.append(self._misp_attribute("mutex", "Artifacts dropped", value, profile))
            for technique in profile.attack_techniques:
                attributes.append(self._misp_attribute("text", "External analysis", technique, profile))
            events.append(
                {
                    "Event": {
                        "info": f"STAS campaign correlation {profile.campaign_id}",
                        "date": self._now()[:10],
                        "distribution": "0",
                        "threat_level_id": "2",
                        "analysis": "1",
                        "Attribute": attributes,
                        "Tag": [{"name": f"stas:campaign=\"{profile.campaign_id}\""}],
                    }
                }
            )
        return {"response": events}

    def sample_from_analysis(self, analysis: Dict[str, Any]) -> MalwareSample:
        sample_data = analysis.get("sample") or analysis
        sample_id = str(sample_data.get("id") or sample_data.get("sample_id") or sample_data.get("sha256") or self._hash_json(analysis))
        iocs = analysis.get("iocs") or {}
        static = analysis.get("static") or {}
        ml = analysis.get("ml_prediction") or {}
        dynamic = analysis.get("dynamic") or {}

        return MalwareSample(
            sample_id=sample_id,
            name=str(sample_data.get("name") or sample_id),
            sha256=str(sample_data.get("sha256") or analysis.get("sha256") or ""),
            md5=str(sample_data.get("md5") or analysis.get("md5") or ""),
            first_seen=sample_data.get("first_seen") or analysis.get("first_seen") or self._now(),
            last_seen=sample_data.get("last_seen") or analysis.get("last_seen") or self._now(),
            compile_timestamp=self._parse_timestamp(sample_data.get("compile_timestamp") or static.get("compile_timestamp")),
            family=str(ml.get("likely_family") or analysis.get("family") or ""),
            archetype=str(ml.get("archetype") or analysis.get("archetype") or ""),
            risk_score=int((analysis.get("risk_scores") or {}).get("overall") or sample_data.get("risk_score") or 0),
            imphash=str(sample_data.get("imphash") or static.get("imphash") or analysis.get("imphash") or ""),
            packer=str(static.get("packer_detected") or static.get("packer") or analysis.get("packer") or ""),
            signer=str(sample_data.get("signer") or static.get("signer") or static.get("authenticode_signer") or ""),
            fuzzy_hash=str(sample_data.get("ssdeep") or sample_data.get("tlsh") or static.get("ssdeep") or static.get("tlsh") or ""),
            domains=self._set_from(iocs.get("domains")) | self._typed_iocs(analysis, "DOMAIN"),
            ips=self._set_from(iocs.get("ips") or iocs.get("ip_addresses")) | self._typed_iocs(analysis, "IP"),
            mutexes=self._set_from(iocs.get("mutexes") or iocs.get("mutex")) | self._typed_iocs(analysis, "MUTEX"),
            named_pipes=self._set_from(iocs.get("named_pipes") or iocs.get("pipes")) | self._typed_iocs(analysis, "PIPE"),
            attack_techniques=self._attack_set(analysis.get("attack_techniques")),
            strings=self._useful_strings(static.get("strings") or analysis.get("strings") or []),
            raw=analysis,
        )

    def fuzzy_similarity(self, left: str, right: str) -> float:
        if not left or not right:
            return 0.0
        if left == right:
            return 100.0
        left_tokens = self._fuzzy_tokens(left)
        right_tokens = self._fuzzy_tokens(right)
        if not left_tokens or not right_tokens:
            return 0.0
        return 100.0 * len(left_tokens & right_tokens) / len(left_tokens | right_tokens)

    def _communities(self) -> List[Set[str]]:
        if self.graph.number_of_nodes() == 0:
            return []
        if self.graph.number_of_edges() == 0:
            return [{node} for node in self.graph.nodes]
        try:
            return [set(item) for item in nx.community.louvain_communities(self.graph, weight="weight", seed=42)]
        except AttributeError:
            return [set(item) for item in nx.community.greedy_modularity_communities(self.graph, weight="weight")]

    def _build_campaign_profile(self, sample_ids: List[str]) -> CampaignProfile:
        samples = [self.samples[sample_id] for sample_id in sample_ids]
        campaign_id = "STAS-CAMP-" + self._uuidish("|".join(sample_ids))[:8].upper()
        first_seen = min((sample.first_seen for sample in samples if sample.first_seen), default=None)
        last_seen = max((sample.last_seen for sample in samples if sample.last_seen), default=None)
        shared_infra = self._shared_infrastructure(samples)
        attack_techniques = sorted(set().union(*(sample.attack_techniques for sample in samples)))
        confidence = self._campaign_confidence(sample_ids, shared_infra)
        families = self._counts(sample.family for sample in samples if sample.family)
        archetypes = self._counts(sample.archetype for sample in samples if sample.archetype)
        hints = self._attribution_hints(families, archetypes, shared_infra)
        return CampaignProfile(
            campaign_id=campaign_id,
            sample_ids=sample_ids,
            first_seen=first_seen,
            last_seen=last_seen,
            shared_infrastructure=shared_infra,
            attack_techniques=attack_techniques,
            confidence_score=confidence,
            attribution_hints=hints,
            families=families,
            archetypes=archetypes,
        )

    def _shared_infrastructure(self, samples: List[MalwareSample]) -> Dict[str, List[str]]:
        def shared(attr: str) -> List[str]:
            sets = [getattr(sample, attr) for sample in samples if getattr(sample, attr)]
            if len(sets) < 2:
                return []
            counts: Dict[str, int] = {}
            for values in sets:
                for value in values:
                    counts[value] = counts.get(value, 0) + 1
            return sorted(value for value, count in counts.items() if count >= 2)

        return {
            "ips": shared("ips"),
            "domains": shared("domains"),
            "mutexes": shared("mutexes"),
            "named_pipes": shared("named_pipes"),
        }

    def _campaign_confidence(self, sample_ids: List[str], shared_infra: Dict[str, List[str]]) -> int:
        if len(sample_ids) == 1:
            return 25
        edge_weights = [
            data.get("weight", 0)
            for left, right, data in self.graph.edges(data=True)
            if left in sample_ids and right in sample_ids
        ]
        avg_weight = sum(edge_weights) / max(1, len(edge_weights))
        infra_bonus = min(25, 5 * sum(len(values) for values in shared_infra.values()))
        density = nx.density(self.graph.subgraph(sample_ids)) if len(sample_ids) > 1 else 0
        return int(max(0, min(100, avg_weight * 2.5 + infra_bonus + density * 20)))

    def _attribution_hints(self, families: Dict[str, int], archetypes: Dict[str, int], shared_infra: Dict[str, List[str]]) -> List[str]:
        hints = []
        if families:
            family = max(families, key=families.get)
            hints.append(f"Dominant family prediction: {family} ({families[family]} samples)")
        if archetypes:
            archetype = max(archetypes, key=archetypes.get)
            hints.append(f"Dominant behavioral archetype: {archetype}")
        if shared_infra.get("domains") or shared_infra.get("ips"):
            hints.append("Shared C2 infrastructure suggests coordinated operator control.")
        if shared_infra.get("mutexes") or shared_infra.get("named_pipes"):
            hints.append("Shared runtime artifacts suggest common builder or codebase.")
        return hints or ["Insufficient evidence for actor attribution beyond sample correlation."]

    def _persist_correlations(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM correlations")
        for left, right, data in self.graph.edges(data=True):
            conn.execute(
                "INSERT INTO correlations(sample_a, sample_b, weight, signals_json) VALUES (?, ?, ?, ?)",
                (left, right, int(data.get("weight", 0)), json.dumps(data.get("signals", []))),
            )
        conn.commit()
        conn.close()

    def _persist_campaigns(self, profiles: List[CampaignProfile]) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM campaigns")
        for profile in profiles:
            conn.execute(
                """
                INSERT INTO campaigns(
                    campaign_id, sample_ids_json, first_seen, last_seen, shared_infrastructure_json,
                    attack_techniques_json, confidence_score, attribution_hints_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.campaign_id,
                    json.dumps(profile.sample_ids),
                    profile.first_seen,
                    profile.last_seen,
                    json.dumps(profile.shared_infrastructure),
                    json.dumps(profile.attack_techniques),
                    profile.confidence_score,
                    json.dumps(profile.attribution_hints),
                ),
            )
        conn.commit()
        conn.close()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS samples(
                sample_id TEXT PRIMARY KEY,
                name TEXT,
                sha256 TEXT,
                md5 TEXT,
                first_seen TEXT,
                last_seen TEXT,
                compile_timestamp INTEGER,
                family TEXT,
                archetype TEXT,
                risk_score INTEGER,
                imphash TEXT,
                packer TEXT,
                signer TEXT,
                fuzzy_hash TEXT,
                raw_json TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs(
                sample_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                UNIQUE(sample_id, ioc_type, value)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS correlations(
                sample_a TEXT NOT NULL,
                sample_b TEXT NOT NULL,
                weight INTEGER NOT NULL,
                signals_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS campaigns(
                campaign_id TEXT PRIMARY KEY,
                sample_ids_json TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                shared_infrastructure_json TEXT NOT NULL,
                attack_techniques_json TEXT NOT NULL,
                confidence_score INTEGER NOT NULL,
                attribution_hints_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()

    def _row_to_sample(self, row: sqlite3.Row) -> MalwareSample:
        raw = json.loads(row["raw_json"] or "{}")
        sample = self.sample_from_analysis(raw) if raw else MalwareSample(sample_id=row["sample_id"])
        sample.sample_id = row["sample_id"]
        sample.name = row["name"] or sample.name
        sample.sha256 = row["sha256"] or sample.sha256
        sample.md5 = row["md5"] or sample.md5
        sample.first_seen = row["first_seen"] or sample.first_seen
        sample.last_seen = row["last_seen"] or sample.last_seen
        sample.compile_timestamp = row["compile_timestamp"] or sample.compile_timestamp
        sample.family = row["family"] or sample.family
        sample.archetype = row["archetype"] or sample.archetype
        sample.risk_score = row["risk_score"] or sample.risk_score
        sample.imphash = row["imphash"] or sample.imphash
        sample.packer = row["packer"] or sample.packer
        sample.signer = row["signer"] or sample.signer
        sample.fuzzy_hash = row["fuzzy_hash"] or sample.fuzzy_hash
        return sample

    def _get_sample(self, sample_id: str) -> MalwareSample:
        if sample_id not in self.samples:
            self.load_from_database()
        if sample_id not in self.samples:
            raise KeyError(f"Unknown sample_id: {sample_id}")
        return self.samples[sample_id]

    def _signal(self, name: str, values: List[str]) -> Dict[str, Any]:
        return {"name": name, "weight": SIGNAL_WEIGHTS[name], "values": values}

    def _compile_times_close(self, left: Optional[int], right: Optional[int]) -> bool:
        if left is None or right is None:
            return False
        return abs(int(left) - int(right)) <= 24 * 60 * 60

    def _string_overlap(self, left: Set[str], right: Set[str]) -> Set[str]:
        common = left & right
        return {value for value in common if len(value) >= 6}

    def _fuzzy_tokens(self, value: str) -> Set[str]:
        cleaned = "".join(ch.lower() for ch in value if ch.isalnum())
        if len(cleaned) < 7:
            return {cleaned} if cleaned else set()
        return {cleaned[index : index + 7] for index in range(0, len(cleaned) - 6)}

    def _set_from(self, value: Any) -> Set[str]:
        if value is None:
            return set()
        if isinstance(value, str):
            return {value} if value else set()
        if isinstance(value, dict):
            return {str(item) for item in value.values() if item}
        if isinstance(value, Iterable):
            result = set()
            for item in value:
                if isinstance(item, dict):
                    text = item.get("value") or item.get("name") or item.get("path")
                    if text:
                        result.add(str(text))
                elif item:
                    result.add(str(item))
            return result
        return {str(value)}

    def _typed_iocs(self, analysis: Dict[str, Any], wanted: str) -> Set[str]:
        values = set()
        raw = analysis.get("iocs")
        if not isinstance(raw, list):
            return values
        for item in raw:
            if not isinstance(item, dict):
                continue
            ioc_type = str(item.get("type") or item.get("ioc_type") or "").upper()
            value = item.get("value") or item.get("ioc_value")
            if wanted in ioc_type and value:
                values.add(str(value))
        return values

    def _attack_set(self, value: Any) -> Set[str]:
        result = set()
        if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
            return result
        for item in value:
            if isinstance(item, dict):
                technique = item.get("id")
            else:
                technique = item
            if technique:
                result.add(str(technique).upper())
        return result

    def _useful_strings(self, values: Any) -> Set[str]:
        strings = self._set_from(values)
        return {value for value in strings if len(value) >= 6 and len(value) <= 200}

    def _parse_timestamp(self, value: Any) -> Optional[int]:
        if value is None or value == "":
            return None
        if isinstance(value, (int, float)):
            number = int(value)
            return number // 1000 if number > 10_000_000_000 else number
        if isinstance(value, str):
            if value.isdigit():
                return self._parse_timestamp(int(value))
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    return int(datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).timestamp())
                except ValueError:
                    pass
        return None

    def _counts(self, values: Iterable[str]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for value in values:
            counts[value] = counts.get(value, 0) + 1
        return counts

    def _sample_to_json(self, sample: MalwareSample) -> Dict[str, Any]:
        data = asdict(sample)
        for key in ["domains", "ips", "mutexes", "named_pipes", "attack_techniques", "strings"]:
            data[key] = sorted(data[key])
        return data

    def _misp_attribute(self, attr_type: str, category: str, value: str, profile: CampaignProfile) -> Dict[str, Any]:
        return {
            "type": attr_type,
            "category": category,
            "value": value,
            "to_ids": profile.confidence_score >= 55,
            "comment": f"Shared indicator in {profile.campaign_id}",
        }

    def _html_template(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> str:
        return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>STAS Campaign Graph</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body {{ margin:0; background:#0D1117; color:#F8FAFC; font-family:Arial, sans-serif; }}
    #graph {{ width:100vw; height:100vh; }}
    #details {{ position:absolute; right:16px; top:16px; width:360px; max-height:80vh; overflow:auto;
      background:#161B22; border:1px solid #30363D; border-radius:8px; padding:12px; white-space:pre-wrap; }}
  </style>
</head>
<body>
  <div id="graph"></div>
  <pre id="details">Click a node to inspect sample details.</pre>
  <script>
    const rawNodes = {json.dumps(nodes)};
    const rawEdges = {json.dumps(edges)};
    const nodes = new vis.DataSet(rawNodes.map(n => ({{
      id:n.id, label:n.label, color:n.color, title:n.id, value: Math.max(10, Number(n.details.risk_score || 0))
    }})));
    const edges = new vis.DataSet(rawEdges.map(e => ({{
      from:e.source, to:e.target, value:e.weight, title: JSON.stringify(e.signals, null, 2)
    }})));
    const network = new vis.Network(document.getElementById('graph'), {{nodes, edges}}, {{
      nodes: {{ shape:'dot', font:{{color:'#F8FAFC'}} }},
      edges: {{ color:'#8B949E', smooth:true }},
      physics: {{ stabilization:true }}
    }});
    network.on('click', params => {{
      if (params.nodes.length) {{
        const node = rawNodes.find(n => n.id === params.nodes[0]);
        document.getElementById('details').textContent = JSON.stringify(node.details, null, 2);
      }}
    }});
  </script>
</body>
</html>
"""

    def _color_for(self, value: Any) -> str:
        palette = ["#3B82F6", "#10B981", "#F97316", "#8B5CF6", "#EAB308", "#EF4444", "#14B8A6"]
        if isinstance(value, int):
            if value >= 80:
                return "#EF4444"
            if value >= 60:
                return "#F97316"
            if value >= 35:
                return "#EAB308"
            return "#3B82F6"
        digest = hashlib.sha256(str(value).encode("utf-8")).digest()
        return palette[digest[0] % len(palette)]

    def _hash_json(self, value: Dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()

    def _uuidish(self, value: str) -> str:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return f"{digest[0:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}"

    def _now(self) -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    base = {
        "static": {"imphash": "abc", "packer_detected": "UPX", "strings": ["campaign_mutex", "loader_config", "shared_path"]},
        "iocs": {"domains": ["c2.example.com"], "ips": ["10.0.0.5"], "mutexes": ["Global\\campaign_mutex"]},
        "attack_techniques": [{"id": "T1055"}, {"id": "T1071"}],
        "ml_prediction": {"likely_family": "ExampleRAT", "archetype": "RAT"},
        "risk_scores": {"overall": 80},
    }
    samples = []
    for index in range(3):
        item = json.loads(json.dumps(base))
        item["sample"] = {"name": f"sample{index}.exe", "sha256": hashlib.sha256(str(index).encode()).hexdigest()}
        item["static"]["compile_timestamp"] = 1710000000 + index * 3600
        samples.append(item)
    graph = CampaignGraph("/tmp/stas_campaign_demo.db")
    graph.build_graph(samples)
    for profile in graph.detect_campaigns():
        print(json.dumps(asdict(profile), indent=2))
