import json
import os
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler


FEATURE_SCHEMA = {
    "import_categories": [
        "MEMORY",
        "NETWORK",
        "REGISTRY",
        "CRYPTO",
        "PERSISTENCE",
        "PROCESS_INJECTION",
        "EVASION",
        "KEYLOGGING",
        "SCREENSHOT",
        "FILE_OPS",
    ],
    "attack_techniques": [
        "T1003",
        "T1027",
        "T1055",
        "T1071",
        "T1105",
        "T1112",
        "T1113",
        "T1115",
        "T1543.003",
        "T1547.001",
        "T1566",
        "T1486",
    ],
    "ioc_types": [
        "IPV4",
        "IPV6",
        "DOMAIN",
        "URL",
        "ONION",
        "C2_DGA_DOMAIN",
        "WINDOWS_PATH",
        "REGISTRY_KEY",
        "MUTEX",
        "NAMED_PIPE",
        "BITCOIN",
        "ETHEREUM",
        "MONERO",
        "API_KEY",
        "JWT",
        "EMAIL",
        "TELEGRAM_BOT_TOKEN",
        "DISCORD_WEBHOOK",
    ],
    "behavioral_events": [
        "ProcessCreate",
        "FileCreate",
        "FileDelete",
        "RegistryModify",
        "NetworkConnect",
        "ServiceCreate",
        "ScheduledTaskCreate",
        "RemoteThreadCreate",
        "CredentialAccess",
        "ScreenCapture",
        "Keylogging",
        "CryptoOperation",
    ],
    "risk_scores": [
        "Stealth",
        "Persistence",
        "Propagation",
        "Exfiltration",
        "Injection",
        "CredentialAccess",
        "Ransomware",
    ],
}


FAMILY_ARCHETYPES = {
    "Emotet": "Loader",
    "Ryuk": "Ransomware",
    "Cobalt Strike": "Backdoor",
    "Mimikatz": "Stealer",
    "Metasploit": "Backdoor",
    "AsyncRAT": "RAT",
    "RedLine": "Stealer",
    "AgentTesla": "Stealer",
    "Formbook": "Stealer",
}


@dataclass
class ClusterResult:
    labels: List[int]
    centroids: Dict[int, List[float]]
    outlier_indices: List[int]
    cluster_sizes: Dict[int, int]


class BehaviorAnalyzer:
    def __init__(
        self,
        db_path: Optional[str] = None,
        baseline_path: Optional[str] = None,
        random_state: int = 42,
    ):
        here = os.path.dirname(os.path.abspath(__file__))
        self.db_path = db_path or os.path.abspath(os.path.join(here, "../../data/family_profiles.db"))
        self.baseline_path = baseline_path or os.path.abspath(os.path.join(here, "../../data/baseline_data.csv"))
        self.random_state = random_state
        self.feature_names = self._build_feature_names()
        self.scaler = StandardScaler()
        self.cluster_scaler = StandardScaler()
        self.isolation_forest: Optional[IsolationForest] = None
        self.baseline_matrix: Optional[np.ndarray] = None

        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        self.prepopulate_family_profiles()
        self.train_anomaly_detector()

    def analyze(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        family_matches = self.compute_family_similarity(feature_vector)
        anomaly = self.score_anomaly(feature_vector)
        likely_family = family_matches[0] if family_matches else {
            "family": "Unknown",
            "similarity": 0.0,
            "matching_features": [],
        }
        novelty_score = round(float(1.0 - likely_family["similarity"]), 4)
        archetype = self.predict_archetype(feature_vector, likely_family["family"])
        confidence = self._confidence_level(likely_family["similarity"], anomaly["anomaly_score"], novelty_score)

        return {
            "likely_malware_family": likely_family["family"],
            "family_probability": round(float(likely_family["similarity"] * 100.0), 2),
            "family_matches": family_matches,
            "behavioral_archetype": archetype,
            "novelty_score": novelty_score,
            "anomaly_score": anomaly["anomaly_score"],
            "anomalous_features": anomaly["anomalous_features"],
            "confidence_level": confidence,
        }

    def compute_family_similarity(self, feature_vector: Dict[str, Any], top_n: Optional[int] = None) -> List[Dict[str, Any]]:
        sample = self.vectorize(feature_vector).reshape(1, -1)
        profiles = self.load_family_profiles()
        results = []

        for family, profile_vector in profiles:
            profile = np.array(profile_vector, dtype=float).reshape(1, -1)
            similarity = float(cosine_similarity(sample, profile)[0][0])
            results.append(
                {
                    "family": family,
                    "similarity": round(max(0.0, similarity), 4),
                    "matching_features": self._matching_features(sample.flatten(), profile.flatten()),
                }
            )

        results.sort(key=lambda item: item["similarity"], reverse=True)
        return results[:top_n] if top_n else results

    def cluster_samples(
        self,
        feature_vectors: Sequence[Dict[str, Any]],
        eps: float = 1.15,
        min_samples: int = 3,
    ) -> ClusterResult:
        if not feature_vectors:
            return ClusterResult([], {}, [], {})

        matrix = np.vstack([self.vectorize(item) for item in feature_vectors])
        scaled = self.cluster_scaler.fit_transform(matrix)

        model = DBSCAN(eps=eps, min_samples=min_samples, metric="euclidean")
        labels = model.fit_predict(scaled)

        centroids: Dict[int, List[float]] = {}
        cluster_sizes: Dict[int, int] = {}
        for label in sorted(set(labels)):
            indices = np.where(labels == label)[0]
            cluster_sizes[int(label)] = int(len(indices))
            if label == -1:
                continue
            centroids[int(label)] = np.mean(matrix[indices], axis=0).round(5).tolist()

        outliers = [int(index) for index, label in enumerate(labels) if label == -1]
        return ClusterResult(
            labels=[int(label) for label in labels],
            centroids=centroids,
            outlier_indices=outliers,
            cluster_sizes=cluster_sizes,
        )

    def cluster_samples_dict(self, feature_vectors: Sequence[Dict[str, Any]], **kwargs: Any) -> Dict[str, Any]:
        result = self.cluster_samples(feature_vectors, **kwargs)
        return {
            "labels": result.labels,
            "centroids": result.centroids,
            "outlier_indices": result.outlier_indices,
            "cluster_sizes": result.cluster_sizes,
        }

    def train_anomaly_detector(self, benign_vectors: Optional[Sequence[Dict[str, Any]]] = None) -> None:
        if benign_vectors:
            matrix = np.vstack([self.vectorize(item) for item in benign_vectors])
        elif os.path.exists(self.baseline_path):
            matrix = self._load_baseline_csv(self.baseline_path)
        else:
            matrix = self._synthetic_benign_baseline()

        self.baseline_matrix = matrix
        scaled = self.scaler.fit_transform(matrix)
        self.isolation_forest = IsolationForest(
            n_estimators=200,
            contamination=0.08,
            random_state=self.random_state,
        )
        self.isolation_forest.fit(scaled)

    def score_anomaly(self, feature_vector: Dict[str, Any], top_n_features: int = 8) -> Dict[str, Any]:
        if self.isolation_forest is None or self.baseline_matrix is None:
            self.train_anomaly_detector()

        vector = self.vectorize(feature_vector).reshape(1, -1)
        scaled = self.scaler.transform(vector)
        raw_score = float(self.isolation_forest.decision_function(scaled)[0])
        anomaly_score = float(np.clip((0.18 - raw_score) / 0.36, 0.0, 1.0))

        baseline_mean = np.mean(self.baseline_matrix, axis=0)
        baseline_std = np.maximum(np.std(self.baseline_matrix, axis=0), 0.25)
        z_scores = np.abs((vector.flatten() - baseline_mean) / baseline_std)
        top_indices = np.argsort(z_scores)[::-1][:top_n_features]
        anomalous_features = [
            {
                "feature": self.feature_names[int(index)],
                "z_score": round(float(z_scores[int(index)]), 3),
                "value": round(float(vector.flatten()[int(index)]), 4),
                "baseline_mean": round(float(baseline_mean[int(index)]), 4),
            }
            for index in top_indices
            if z_scores[int(index)] >= 1.5
        ]

        return {
            "anomaly_score": round(anomaly_score, 4),
            "is_anomalous": anomaly_score >= 0.65,
            "anomalous_features": anomalous_features,
        }

    def predict_archetype(self, feature_vector: Dict[str, Any], likely_family: Optional[str] = None) -> str:
        if likely_family in FAMILY_ARCHETYPES:
            return FAMILY_ARCHETYPES[likely_family]

        imports = self._upper_count_dict(feature_vector.get("import_categories", {}))
        techniques = {str(item).upper() for item in feature_vector.get("attack_techniques", [])}
        iocs = {str(item).upper() for item in feature_vector.get("ioc_types", [])}
        events = {str(item).upper() for item in feature_vector.get("behavioral_events", [])}
        risks = self._upper_count_dict(feature_vector.get("risk_scores", {}))

        if imports.get("CRYPTO", 0) and imports.get("FILE_OPS", 0) and ("T1486" in techniques or risks.get("RANSOMWARE", 0) >= 50):
            return "Ransomware"
        if imports.get("KEYLOGGING", 0) or "KEYLOGGING" in events or {"API_KEY", "JWT"} & iocs:
            return "Stealer"
        if imports.get("NETWORK", 0) and (imports.get("KEYLOGGING", 0) or imports.get("SCREENSHOT", 0)):
            return "RAT"
        if imports.get("PERSISTENCE", 0) and imports.get("NETWORK", 0):
            return "Backdoor"
        if imports.get("PROCESS_INJECTION", 0) and imports.get("MEMORY", 0):
            return "Loader"
        if "C2_DGA_DOMAIN" in iocs and imports.get("NETWORK", 0):
            return "Dropper"
        if risks.get("PROPAGATION", 0) >= 60:
            return "Worm"
        if imports.get("EVASION", 0) >= 3 and risks.get("STEALTH", 0) >= 70:
            return "Rootkit"
        return "Backdoor" if imports.get("NETWORK", 0) else "Loader"

    def vectorize(self, feature_vector: Dict[str, Any]) -> np.ndarray:
        values: List[float] = []

        import_categories = self._upper_count_dict(feature_vector.get("import_categories", {}))
        values.extend(float(import_categories.get(name, 0.0)) for name in FEATURE_SCHEMA["import_categories"])

        entropy_scores = [float(item) for item in feature_vector.get("entropy_scores", []) if self._is_number(item)]
        values.extend(
            [
                float(np.mean(entropy_scores)) if entropy_scores else 0.0,
                float(np.max(entropy_scores)) if entropy_scores else 0.0,
                float(sum(1 for item in entropy_scores if item > 7.2)),
                float(sum(1 for item in entropy_scores if 6.0 <= item <= 7.2)),
            ]
        )

        techniques = {str(item).upper() for item in feature_vector.get("attack_techniques", [])}
        values.extend(1.0 if name in techniques else 0.0 for name in FEATURE_SCHEMA["attack_techniques"])

        ioc_counts = self._list_counts(feature_vector.get("ioc_types", []))
        values.extend(float(ioc_counts.get(name, 0.0)) for name in FEATURE_SCHEMA["ioc_types"])

        event_counts = self._list_counts(feature_vector.get("behavioral_events", []))
        values.extend(float(event_counts.get(name.upper(), 0.0)) for name in FEATURE_SCHEMA["behavioral_events"])

        risk_scores = self._upper_count_dict(feature_vector.get("risk_scores", {}))
        values.extend(float(risk_scores.get(name.upper(), 0.0)) / 100.0 for name in FEATURE_SCHEMA["risk_scores"])

        return np.array(values, dtype=float)

    def load_family_profiles(self) -> List[Tuple[str, List[float]]]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT family, vector_json FROM family_profiles ORDER BY family").fetchall()
        conn.close()
        return [(family, json.loads(vector_json)) for family, vector_json in rows]

    def upsert_family_profile(self, family: str, feature_vector: Dict[str, Any], archetype: Optional[str] = None) -> None:
        vector = self.vectorize(feature_vector).round(6).tolist()
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            INSERT INTO family_profiles(family, archetype, vector_json, source)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(family) DO UPDATE SET
                archetype=excluded.archetype,
                vector_json=excluded.vector_json,
                source=excluded.source,
                updated_at=CURRENT_TIMESTAMP
            """,
            (family, archetype or FAMILY_ARCHETYPES.get(family, "Unknown"), json.dumps(vector), "builtin"),
        )
        conn.commit()
        conn.close()

    def prepopulate_family_profiles(self) -> None:
        for family, profile in self._builtin_profiles().items():
            self.upsert_family_profile(family, profile, FAMILY_ARCHETYPES.get(family))

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS family_profiles(
                family TEXT PRIMARY KEY,
                archetype TEXT NOT NULL,
                vector_json TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'builtin',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
        conn.close()

    def _build_feature_names(self) -> List[str]:
        names = [f"imports:{name}" for name in FEATURE_SCHEMA["import_categories"]]
        names.extend(["entropy:mean", "entropy:max", "entropy:high_sections", "entropy:borderline_sections"])
        names.extend(f"attack:{name}" for name in FEATURE_SCHEMA["attack_techniques"])
        names.extend(f"ioc:{name}" for name in FEATURE_SCHEMA["ioc_types"])
        names.extend(f"event:{name}" for name in FEATURE_SCHEMA["behavioral_events"])
        names.extend(f"risk:{name}" for name in FEATURE_SCHEMA["risk_scores"])
        return names

    def _matching_features(self, sample: np.ndarray, profile: np.ndarray) -> List[str]:
        groups = {
            "imports": slice(0, 10),
            "packed_entropy": slice(10, 14),
            "attack_techniques": slice(14, 26),
            "iocs": slice(26, 44),
            "network_behavior": self._feature_indices(["imports:NETWORK", "event:NetworkConnect", "ioc:DOMAIN", "ioc:URL"]),
            "persistence": self._feature_indices(["imports:PERSISTENCE", "imports:REGISTRY", "attack:T1547.001", "attack:T1543.003"]),
            "credential_access": self._feature_indices(["attack:T1003", "risk:CredentialAccess", "event:CredentialAccess"]),
            "evasion": self._feature_indices(["imports:EVASION", "attack:T1027", "risk:Stealth"]),
        }

        matches = []
        for name, indices in groups.items():
            if isinstance(indices, slice):
                left = sample[indices]
                right = profile[indices]
            else:
                left = sample[indices]
                right = profile[indices]
            if left.size == 0 or right.size == 0:
                continue
            shared = np.minimum(left, right).sum()
            profile_weight = right.sum() + 1e-6
            if shared / profile_weight >= 0.35:
                matches.append(name)
        return matches

    def _feature_indices(self, names: Sequence[str]) -> List[int]:
        lookup = {name.upper(): index for index, name in enumerate(self.feature_names)}
        return [lookup[name.upper()] for name in names if name.upper() in lookup]

    def _load_baseline_csv(self, path: str) -> np.ndarray:
        data = pd.read_csv(path)
        if all(name in data.columns for name in self.feature_names):
            return data[self.feature_names].astype(float).to_numpy()

        numeric = data.select_dtypes(include=[np.number]).to_numpy(dtype=float)
        if numeric.size and numeric.shape[1] == len(self.feature_names):
            return numeric

        return self._synthetic_benign_baseline()

    def _synthetic_benign_baseline(self) -> np.ndarray:
        rng = np.random.default_rng(self.random_state)
        rows = []
        for _ in range(160):
            vector = np.zeros(len(self.feature_names), dtype=float)
            vector[0] = rng.integers(0, 2)  # MEMORY
            vector[1] = rng.integers(0, 2)  # NETWORK
            vector[2] = rng.integers(0, 2)  # REGISTRY
            vector[9] = rng.integers(1, 4)  # FILE_OPS
            vector[10] = rng.uniform(3.5, 5.8)
            vector[11] = rng.uniform(4.5, 6.4)
            vector[26] = rng.integers(0, 2)  # IPV4
            vector[28] = rng.integers(0, 2)  # DOMAIN
            vector[44] = rng.integers(1, 4)  # ProcessCreate
            vector[45] = rng.integers(1, 4)  # FileCreate
            vector[-7:] = rng.uniform(0.0, 0.25, 7)
            rows.append(vector)
        return np.vstack(rows)

    def _builtin_profiles(self) -> Dict[str, Dict[str, Any]]:
        return {
            "Emotet": {
                "import_categories": {"NETWORK": 5, "PERSISTENCE": 3, "REGISTRY": 4, "FILE_OPS": 5, "EVASION": 2},
                "entropy_scores": [6.7, 7.1, 5.4],
                "attack_techniques": ["T1071", "T1105", "T1547.001", "T1566"],
                "ioc_types": ["DOMAIN", "URL", "C2_DGA_DOMAIN", "EMAIL"],
                "behavioral_events": ["NetworkConnect", "RegistryModify", "FileCreate", "ProcessCreate"],
                "risk_scores": {"Persistence": 75, "Exfiltration": 45, "Stealth": 55},
            },
            "Ryuk": {
                "import_categories": {"CRYPTO": 6, "FILE_OPS": 8, "PROCESS_INJECTION": 2, "EVASION": 3},
                "entropy_scores": [7.4, 7.6, 6.8],
                "attack_techniques": ["T1486", "T1027", "T1055"],
                "ioc_types": ["WINDOWS_PATH", "BITCOIN", "REGISTRY_KEY"],
                "behavioral_events": ["FileCreate", "FileDelete", "CryptoOperation", "ProcessCreate"],
                "risk_scores": {"Ransomware": 95, "Stealth": 70, "Persistence": 40},
            },
            "Cobalt Strike": {
                "import_categories": {"NETWORK": 7, "PROCESS_INJECTION": 6, "MEMORY": 5, "EVASION": 5},
                "entropy_scores": [6.8, 7.3, 6.2],
                "attack_techniques": ["T1055", "T1071", "T1027"],
                "ioc_types": ["DOMAIN", "URL", "IPV4", "NAMED_PIPE"],
                "behavioral_events": ["NetworkConnect", "RemoteThreadCreate", "ProcessCreate"],
                "risk_scores": {"Stealth": 85, "Injection": 90, "Exfiltration": 60},
            },
            "Mimikatz": {
                "import_categories": {"PROCESS_INJECTION": 3, "MEMORY": 4, "EVASION": 3, "REGISTRY": 2},
                "entropy_scores": [5.8, 6.4, 4.9],
                "attack_techniques": ["T1003", "T1055"],
                "ioc_types": ["WINDOWS_PATH"],
                "behavioral_events": ["CredentialAccess", "ProcessCreate"],
                "risk_scores": {"CredentialAccess": 95, "Stealth": 45},
            },
            "Metasploit": {
                "import_categories": {"NETWORK": 6, "MEMORY": 5, "PROCESS_INJECTION": 4, "EVASION": 3},
                "entropy_scores": [6.5, 6.9, 5.8],
                "attack_techniques": ["T1055", "T1071", "T1105"],
                "ioc_types": ["IPV4", "URL", "NAMED_PIPE"],
                "behavioral_events": ["NetworkConnect", "RemoteThreadCreate", "ProcessCreate"],
                "risk_scores": {"Injection": 75, "Stealth": 55},
            },
            "AsyncRAT": {
                "import_categories": {"NETWORK": 5, "KEYLOGGING": 4, "SCREENSHOT": 3, "PERSISTENCE": 2},
                "entropy_scores": [6.0, 6.5, 5.2],
                "attack_techniques": ["T1071", "T1113", "T1115", "T1547.001"],
                "ioc_types": ["DOMAIN", "IPV4", "URL"],
                "behavioral_events": ["NetworkConnect", "Keylogging", "ScreenCapture", "RegistryModify"],
                "risk_scores": {"Persistence": 60, "Exfiltration": 80},
            },
            "RedLine": {
                "import_categories": {"NETWORK": 4, "FILE_OPS": 4, "CRYPTO": 2, "EVASION": 2},
                "entropy_scores": [6.6, 7.0, 5.7],
                "attack_techniques": ["T1003", "T1071", "T1027"],
                "ioc_types": ["DOMAIN", "URL", "API_KEY", "JWT", "WINDOWS_PATH"],
                "behavioral_events": ["CredentialAccess", "NetworkConnect", "FileCreate"],
                "risk_scores": {"CredentialAccess": 85, "Exfiltration": 75, "Stealth": 50},
            },
            "AgentTesla": {
                "import_categories": {"NETWORK": 4, "KEYLOGGING": 5, "SCREENSHOT": 2, "FILE_OPS": 3},
                "entropy_scores": [5.9, 6.4, 5.1],
                "attack_techniques": ["T1115", "T1113", "T1071"],
                "ioc_types": ["EMAIL", "DOMAIN", "API_KEY"],
                "behavioral_events": ["Keylogging", "ScreenCapture", "NetworkConnect"],
                "risk_scores": {"CredentialAccess": 70, "Exfiltration": 85},
            },
            "Formbook": {
                "import_categories": {"NETWORK": 4, "KEYLOGGING": 3, "FILE_OPS": 3, "EVASION": 3},
                "entropy_scores": [6.8, 7.2, 5.8],
                "attack_techniques": ["T1071", "T1115", "T1027"],
                "ioc_types": ["DOMAIN", "URL", "EMAIL"],
                "behavioral_events": ["Keylogging", "NetworkConnect", "FileCreate"],
                "risk_scores": {"CredentialAccess": 75, "Exfiltration": 80, "Stealth": 60},
            },
        }

    def _confidence_level(self, similarity: float, anomaly_score: float, novelty_score: float) -> str:
        if similarity >= 0.78 and anomaly_score >= 0.45:
            return "HIGH"
        if similarity >= 0.58 or anomaly_score >= 0.65:
            return "MEDIUM"
        if novelty_score >= 0.75:
            return "LOW"
        return "LOW"

    def _upper_count_dict(self, value: Any) -> Dict[str, float]:
        if not isinstance(value, dict):
            return {}
        return {str(key).upper(): float(count) for key, count in value.items() if self._is_number(count)}

    def _list_counts(self, values: Any) -> Dict[str, float]:
        counts: Dict[str, float] = {}
        if not isinstance(values, Iterable) or isinstance(values, (str, bytes)):
            return counts
        for item in values:
            key = str(item).upper()
            counts[key] = counts.get(key, 0.0) + 1.0
        return counts

    def _is_number(self, value: Any) -> bool:
        try:
            float(value)
            return True
        except (TypeError, ValueError):
            return False


if __name__ == "__main__":
    analyzer = BehaviorAnalyzer()
    sample = {
        "import_categories": {"NETWORK": 5, "MEMORY": 4, "PROCESS_INJECTION": 5, "EVASION": 4},
        "entropy_scores": [6.9, 7.4, 6.2],
        "attack_techniques": ["T1055", "T1071"],
        "ioc_types": ["DOMAIN", "URL", "IPV4"],
        "behavioral_events": ["NetworkConnect", "RemoteThreadCreate", "ProcessCreate"],
        "risk_scores": {"Stealth": 80, "Injection": 90, "Exfiltration": 50},
    }
    print(json.dumps(analyzer.analyze(sample), indent=2))
