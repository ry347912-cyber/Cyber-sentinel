"""
NetGuard IDS — MongoDB Database Layer
"""

from pymongo import MongoClient, DESCENDING
from datetime import datetime
from collections import Counter


class Database:
    def __init__(self, mongo_uri: str):
        self.client = MongoClient(mongo_uri)
        self.db = self.client["netguard"]
        self.alerts = self.db["alerts"]
        self.traffic = self.db["traffic"]

        # Create indexes for fast queries
        self.alerts.create_index([("time", DESCENDING)])
        self.alerts.create_index("src_ip")
        self.alerts.create_index("severity")
        self.alerts.create_index("type")
        print("[DB] Connected to MongoDB.")

    def save_alert(self, alert: dict):
        alert["created_at"] = datetime.utcnow()
        self.alerts.insert_one(alert)

    def get_alerts(self, limit=50, severity=None, attack_type=None, src_ip=None):
        query = {}
        if severity:
            query["severity"] = severity
        if attack_type:
            query["type"] = attack_type
        if src_ip:
            query["src_ip"] = {"$regex": src_ip}

        cursor = self.alerts.find(query, {"_id": 0}).sort("time", DESCENDING).limit(limit)
        return list(cursor)

    def get_severity_counts(self) -> dict:
        pipeline = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
        result = self.alerts.aggregate(pipeline)
        return {doc["_id"]: doc["count"] for doc in result}

    def get_attack_type_counts(self) -> dict:
        pipeline = [{"$group": {"_id": "$type", "count": {"$sum": 1}}}]
        result = self.alerts.aggregate(pipeline)
        return {doc["_id"]: doc["count"] for doc in result}

    def save_traffic_snapshot(self, snapshot: dict):
        snapshot["created_at"] = datetime.utcnow()
        self.traffic.insert_one(snapshot)

    def get_traffic_history(self, limit=60):
        cursor = self.traffic.find({}, {"_id": 0}).sort("created_at", DESCENDING).limit(limit)
        return list(reversed(list(cursor)))
