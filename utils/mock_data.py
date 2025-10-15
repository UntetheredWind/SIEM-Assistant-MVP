import json
from datetime import datetime, timedelta
import random

class MockDataGenerator:
    @staticmethod
    def generate_sample_alerts():
        alerts = [
            {
                "id": "7321",
                "title": "Multiple Web Server 404 Errors from Same Source",
                "severity": "High",
                "source_ip": "89.12.34.56",
                "timestamp": (datetime.now() - timedelta(minutes=5)).isoformat(),
                "rule_level": 13,
                "description": "Excessive 404 errors detected from single source"
            },
            {
                "id": "7322", 
                "title": "Failed SSH Login Attempts",
                "severity": "Medium",
                "source_ip": "192.168.1.100",
                "timestamp": (datetime.now() - timedelta(minutes=10)).isoformat(),
                "rule_level": 8,
                "description": "Multiple failed SSH authentication attempts"
            }
        ]
        return alerts
    
    @staticmethod
    def generate_triage_results(alert):
        if "404" in alert["title"]:
            return {
                "ip_analysis": f"IP {alert['source_ip']} responsible for 98% of 404 errors",
                "history_check": "This IP has never been seen before today",
                "threat_intel": "IP not found in current threat intelligence feeds",
                "suggested_actions": ["Investigate further", "Block IP temporarily", "Check server logs"]
            }
        return {"message": "Standard triage completed"}
