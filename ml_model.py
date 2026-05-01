"""
NetGuard ML Model — Anomaly Detection
Uses a Random Forest Classifier trained on the NSL-KDD / CICIDS dataset.
For demo/project: uses an Isolation Forest for unsupervised anomaly detection.
"""

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import os

ATTACK_LABELS = ["DDoS", "Port Scan", "Brute Force", "SQL Injection", "XSS", "MITM"]
SEVERITY_MAP = {
    "DDoS": "CRITICAL",
    "Port Scan": "MEDIUM",
    "Brute Force": "HIGH",
    "SQL Injection": "HIGH",
    "XSS": "MEDIUM",
    "MITM": "CRITICAL",
}

MODEL_PATH = "ids_model.pkl"
SCALER_PATH = "ids_scaler.pkl"


class MLModel:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self._load_or_train()

    def _load_or_train(self):
        """Load existing model or train a new demo one."""
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
            with open(SCALER_PATH, "rb") as f:
                self.scaler = pickle.load(f)
            print("[ML] Model loaded from disk.")
        else:
            print("[ML] Training new Isolation Forest model...")
            self._train_demo_model()

    def _train_demo_model(self):
        """
        Train on synthetic normal traffic.
        In production: replace with real labeled dataset (NSL-KDD, CICIDS2017).
        """
        np.random.seed(42)
        # Simulate normal traffic features:
        # [pkt_size, protocol, src_port, dst_port, pps, unique_ports, has_payload, tcp_flags]
        normal_traffic = np.column_stack([
            np.random.normal(500, 200, 5000),   # pkt_size
            np.random.choice([6, 17], 5000),    # protocol (TCP/UDP)
            np.random.randint(1024, 65535, 5000),  # src_port
            np.random.choice([80, 443, 22, 53, 8080], 5000),  # dst_port
            np.random.normal(50, 20, 5000),     # packets/sec
            np.random.randint(1, 5, 5000),      # unique ports
            np.ones(5000),                      # has_payload
            np.random.choice([2, 16, 18, 24], 5000),  # TCP flags
        ])

        self.scaler.fit(normal_traffic)
        X_scaled = self.scaler.transform(normal_traffic)

        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,  # expect 5% anomalies
            random_state=42
        )
        self.model.fit(X_scaled)

        # Save model
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump(self.scaler, f)
        print("[ML] Model trained and saved.")

    def predict(self, features: dict) -> dict:
        """
        Predict if a packet set is an attack.
        Returns: { is_attack: bool, attack_type: str, severity: str, confidence: float }
        """
        feature_vector = np.array([[
            features.get("pkt_size", 0),
            features.get("protocol", 6),
            features.get("src_port", 0),
            features.get("dst_port", 0),
            features.get("packets_per_sec", 0),
            features.get("unique_ports", 0),
            features.get("has_payload", 1),
            features.get("tcp_flags", 0),
        ]])

        try:
            scaled = self.scaler.transform(feature_vector)
            prediction = self.model.predict(scaled)[0]   # -1 = anomaly, 1 = normal
            score = self.model.score_samples(scaled)[0]  # more negative = more anomalous

            is_attack = prediction == -1

            if is_attack:
                # Heuristic attack type assignment based on features
                pps = features.get("packets_per_sec", 0)
                unique_ports = features.get("unique_ports", 0)
                dst_port = features.get("dst_port", 0)

                if pps > 300:
                    attack_type = "DDoS"
                elif unique_ports > 15:
                    attack_type = "Port Scan"
                elif dst_port in (22, 3389, 21):
                    attack_type = "Brute Force"
                elif dst_port in (80, 443, 8080):
                    attack_type = "SQL Injection"
                else:
                    attack_type = "MITM"

                confidence = min(1.0, abs(score) / 0.5)
                severity = SEVERITY_MAP.get(attack_type, "MEDIUM")
                return {"is_attack": True, "attack_type": attack_type, "severity": severity, "confidence": round(confidence, 2)}
        except Exception as e:
            print(f"[ML] Prediction error: {e}")

        return {"is_attack": False, "attack_type": None, "severity": None, "confidence": 0.0}

    def retrain(self, labeled_data: list):
        """
        Retrain with labeled data.
        labeled_data: list of { features: dict, label: str }
        """
        print("[ML] Retraining with new labeled data...")
        # TODO: implement supervised retraining with RandomForestClassifier
        pass
