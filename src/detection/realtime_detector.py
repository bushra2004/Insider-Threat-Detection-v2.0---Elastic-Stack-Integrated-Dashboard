import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import redis
from elasticsearch import AsyncElasticsearch
import numpy as np
from scipy import stats
import logging

logger = logging.getLogger(__name__)

class RealtimeDetector:
    def __init__(self):
        self.redis_client = redis.Redis(host='redis', port=6379, decode_responses=True)
        self.es_client = AsyncElasticsearch(['http://elasticsearch:9200'])
        self.running = False
        self.detection_tasks = []
        
        # Threat patterns to detect
        self.threat_patterns = {
            "data_exfiltration": {
                "conditions": ["large_file_transfer", "unusual_time", "external_device"],
                "weight": 0.9
            },
            "privilege_escalation": {
                "conditions": ["multiple_failed_logins", "sudo_usage", "new_admin_account"],
                "weight": 0.8
            },
            "suspicious_access": {
                "conditions": ["access_after_hours", "unauthorized_folder", "multiple_failed_access"],
                "weight": 0.7
            }
        }
    
    async def start(self):
        """Start real-time detection engine"""
        self.running = True
        logger.info("Starting real-time threat detection engine")
        
        # Start multiple detection coroutines
        tasks = [
            asyncio.create_task(self.monitor_user_behavior()),
            asyncio.create_task(self.detect_anomalies()),
            asyncio.create_task(self.check_threat_rules()),
            asyncio.create_task(self.analyze_network_traffic())
        ]
        self.detection_tasks = tasks
        
        # Process Redis queue
        asyncio.create_task(self.process_event_queue())
        
    async def monitor_user_behavior(self):
        """Monitor user behavior for anomalies"""
        while self.running:
            try:
                # Get recent user activities
                query = {
                    "size": 100,
                    "query": {
                        "range": {
                            "@timestamp": {
                                "gte": "now-5m",
                                "lte": "now"
                            }
                        }
                    },
                    "sort": [{"@timestamp": "desc"}]
                }
                
                response = await self.es_client.search(
                    index="user-activities-*",
                    body=query
                )
                
                activities = response['hits']['hits']
                if activities:
                    anomalies = await self.analyze_behavior_patterns(activities)
                    if anomalies:
                        await self.trigger_alerts(anomalies)
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring user behavior: {e}")
                await asyncio.sleep(10)
    
    async def analyze_behavior_patterns(self, activities: List[Dict]) -> List[Dict]:
        """Analyze behavior patterns for anomalies"""
        anomalies = []
        
        # Group by user
        user_activities = {}
        for activity in activities:
            user = activity['_source'].get('user', 'unknown')
            if user not in user_activities:
                user_activities[user] = []
            user_activities[user].append(activity['_source'])
        
        # Analyze each user
        for user, actions in user_activities.items():
            # Check for unusual time access
            unusual_hours = await self.check_unusual_hours(actions)
            if unusual_hours:
                anomalies.append({
                    "user": user,
                    "type": "unusual_hours_access",
                    "severity": "medium",
                    "details": unusual_hours,
                    "timestamp": datetime.now().isoformat()
                })
            
            # Check for data access patterns
            data_access = await self.analyze_data_access(actions)
            if data_access.get('suspicious'):
                anomalies.append({
                    "user": user,
                    "type": "suspicious_data_access",
                    "severity": "high",
                    "details": data_access,
                    "timestamp": datetime.now().isoformat()
                })
            
            # Check for privilege changes
            privilege_changes = await self.check_privilege_changes(actions)
            if privilege_changes:
                anomalies.append({
                    "user": user,
                    "type": "privilege_escalation_attempt",
                    "severity": "critical",
                    "details": privilege_changes,
                    "timestamp": datetime.now().isoformat()
                })
        
        return anomalies
    
    async def check_unusual_hours(self, actions: List[Dict]) -> Optional[Dict]:
        """Check if activities occur during unusual hours"""
        unusual_times = []
        work_hours = range(9, 18)  # 9 AM to 6 PM
        
        for action in actions:
            timestamp = action.get('timestamp')
            if timestamp:
                hour = datetime.fromisoformat(timestamp).hour
                if hour not in work_hours and hour not in [0, 1, 2, 3, 4, 5, 22, 23]:
                    unusual_times.append({
                        "time": timestamp,
                        "action": action.get('action_type'),
                        "resource": action.get('resource')
                    })
        
        if len(unusual_times) > 2:  # More than 2 unusual time activities
            return {
                "count": len(unusual_times),
                "activities": unusual_times[:5]  # Limit to 5 examples
            }
        return None
    
    async def process_event_queue(self):
        """Process events from Redis queue"""
        while self.running:
            try:
                # Get events from Redis queue
                event = self.redis_client.blpop('threat_events', timeout=1)
                if event:
                    _, event_data = event
                    event_json = json.loads(event_data)
                    
                    # Analyze event
                    threat_score = await self.calculate_threat_score(event_json)
                    
                    if threat_score > 0.7:  # High threat threshold
                        alert = {
                            "id": f"alert_{datetime.now().timestamp()}",
                            "title": "High Threat Detected",
                            "description": event_json.get('description', 'Unknown threat'),
                            "severity": "critical" if threat_score > 0.8 else "high",
                            "score": threat_score,
                            "user": event_json.get('user', 'unknown'),
                            "timestamp": datetime.now().isoformat(),
                            "details": event_json,
                            "status": "new"
                        }
                        
                        # Store in Elasticsearch
                        await self.es_client.index(
                            index="threat-alerts",
                            document=alert
                        )
                        
                        # Publish to Redis for real-time dashboard
                        self.redis_client.publish('threat_alerts', json.dumps(alert))
                        
                        # Send email alert
                        await self.send_alert_notification(alert)
                        
            except Exception as e:
                logger.error(f"Error processing event queue: {e}")
                await asyncio.sleep(5)
    
    async def calculate_threat_score(self, event: Dict) -> float:
        """Calculate threat score for an event"""
        score = 0.0
        
        # Check against threat patterns
        for pattern_name, pattern in self.threat_patterns.items():
            pattern_score = 0.0
            conditions_met = 0
            
            for condition in pattern['conditions']:
                if self.check_condition(event, condition):
                    conditions_met += 1
            
            if conditions_met > 0:
                pattern_score = (conditions_met / len(pattern['conditions'])) * pattern['weight']
                score = max(score, pattern_score)
        
        # Add statistical anomaly score
        anomaly_score = await self.calculate_anomaly_score(event)
        score = max(score, anomaly_score)
        
        return min(score, 1.0)  # Cap at 1.0
    
    async def send_alert_notification(self, alert: Dict):
        """Send alert notifications via email and other channels"""
        from src.alerting.alert_manager import AlertManager
        
        alert_manager = AlertManager()
        
        # Prepare notification
        notification = {
            "alert_id": alert['id'],
            "title": alert['title'],
            "severity": alert['severity'],
            "user": alert['user'],
            "timestamp": alert['timestamp'],
            "score": alert['score'],
            "details": alert.get('details', {})
        }
        
        # Send via all configured channels
        await alert_manager.send_alert(notification)
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats from Redis cache"""
        threats = []
        try:
            # Get from Redis sorted set (sorted by timestamp)
            threat_keys = self.redis_client.zrevrange('recent_threats', 0, limit-1)
            
            for key in threat_keys:
                threat_data = self.redis_client.get(f"threat:{key}")
                if threat_data:
                    threats.append(json.loads(threat_data))
        except Exception as e:
            logger.error(f"Error getting recent threats: {e}")
        
        return threats
    
    def is_running(self) -> bool:
        return self.running
    
    async def stop(self):
        """Stop the detection engine"""
        self.running = False
        for task in self.detection_tasks:
            task.cancel()
        await self.es_client.close()