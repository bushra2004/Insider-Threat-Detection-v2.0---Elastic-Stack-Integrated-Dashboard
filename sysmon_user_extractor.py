# Create sysmon_user_extractor.py
import pandas as pd
import json
import re
from datetime import datetime
from collections import defaultdict
import redis
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealUserExtractor:
    def __init__(self, csv_file="uploaded_sysmon.csv"):
        self.csv_file = csv_file
        self.users = {}
        self.user_activities = defaultdict(list)
        self.threat_indicators = []
        
    def parse_sysmon_message(self, message):
        """Parse Sysmon message into structured data"""
        data = {}
        lines = message.split('\n')
        for line in lines:
            if ': ' in line:
                key, value = line.split(': ', 1)
                data[key.strip()] = value.strip()
        return data
    
    def extract_real_users(self):
        """Extract real users from Sysmon data"""
        try:
            df = pd.read_csv(self.csv_file, nrows=5000)  # Read first 5000 rows
            logger.info(f"✅ Loaded {len(df)} rows from Sysmon data")
            
            for index, row in df.iterrows():
                try:
                    message = row['Message']
                    parsed = self.parse_sysmon_message(message)
                    
                    # Extract user if present
                    user = parsed.get('User', '')
                    if user and user not in ['', '-', 'N/A']:
                        # Parse user format: DOMAIN\username
                        if '\\' in user:
                            domain, username = user.split('\\', 1)
                        else:
                            domain = 'LOCAL'
                            username = user
                        
                        # Extract process info
                        process = parsed.get('Image', '')
                        process_name = process.split('\\')[-1] if '\\' in process else process
                        
                        # Create user profile if not exists
                        user_id = f"{domain}_{username}".replace(' ', '_').lower()
                        
                        if user_id not in self.users:
                            self.users[user_id] = {
                                'id': user_id,
                                'username': username,
                                'domain': domain,
                                'full_name': f"{domain}\\{username}",
                                'first_seen': row['TimeCreated'],
                                'last_seen': row['TimeCreated'],
                                'processes': set(),
                                'activities': [],
                                'risk_score': 0.0,
                                'threat_count': 0,
                                'department': self.guess_department(username, domain, process),
                                'role': self.guess_role(process_name, username),
                                'is_service_account': domain in ['NT AUTHORITY', 'SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE']
                            }
                        
                        # Update user info
                        self.users[user_id]['last_seen'] = row['TimeCreated']
                        self.users[user_id]['processes'].add(process_name)
                        
                        # Record activity
                        activity = {
                            'timestamp': row['TimeCreated'],
                            'event_id': row['Id'],
                            'level': row['LevelDisplayName'],
                            'process': process_name,
                            'image': parsed.get('Image', ''),
                            'process_id': parsed.get('ProcessId', ''),
                            'details': parsed
                        }
                        
                        self.users[user_id]['activities'].append(activity)
                        
                        # Check for threat indicators
                        threat = self.detect_threat(activity, user_id)
                        if threat:
                            self.threat_indicators.append(threat)
                            self.users[user_id]['threat_count'] += 1
                            self.users[user_id]['risk_score'] = min(1.0, self.users[user_id]['risk_score'] + 0.1)
                
                except Exception as e:
                    continue
            
            # Calculate final risk scores
            for user_id in self.users:
                user = self.users[user_id]
                
                # Base risk factors
                if user['is_service_account']:
                    user['risk_score'] += 0.2  # Service accounts are higher risk
                
                if len(user['processes']) > 10:
                    user['risk_score'] += 0.1  # Many different processes
                
                # Normalize risk score
                user['risk_score'] = min(1.0, user['risk_score'])
                
                # Determine risk level
                if user['risk_score'] > 0.7:
                    user['risk_level'] = 'critical'
                elif user['risk_score'] > 0.5:
                    user['risk_level'] = 'high'
                elif user['risk_score'] > 0.3:
                    user['risk_level'] = 'medium'
                else:
                    user['risk_level'] = 'low'
                
                # Convert set to list for JSON
                user['processes'] = list(user['processes'])
            
            logger.info(f"✅ Extracted {len(self.users)} real users from Sysmon data")
            logger.info(f"✅ Detected {len(self.threat_indicators)} threat indicators")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error extracting users: {e}")
            return False
    
    def guess_department(self, username, domain, process):
        """Guess user department based on patterns"""
        process_lower = process.lower()
        username_lower = username.lower()
        
        if 'svchost' in process_lower or 'system32' in process_lower:
            return 'IT/System'
        elif 'chrome' in process_lower or 'code.exe' in process_lower or 'python' in process_lower:
            return 'Engineering/Development'
        elif 'onenote' in process_lower or 'excel' in process_lower or 'word' in process_lower:
            return 'Office/Administration'
        elif 'git' in process_lower:
            return 'Development'
        elif domain == 'NT AUTHORITY':
            return 'System Services'
        elif 'dell' in username_lower:
            return 'IT/Hardware'
        else:
            return 'General/Unknown'
    
    def guess_role(self, process, username):
        """Guess user role based on activity"""
        process_lower = process.lower()
        username_lower = username.lower()
        
        if 'svchost' in process_lower or 'service' in username_lower:
            return 'System Service'
        elif 'code.exe' in process_lower or 'python' in process_lower:
            return 'Developer'
        elif 'chrome' in process_lower:
            return 'User/Browser'
        elif 'git' in process_lower:
            return 'Developer/Version Control'
        elif 'conhost' in process_lower or 'cmd' in process_lower:
            return 'Administrator/CLI User'
        elif 'system' in username_lower:
            return 'System Account'
        else:
            return 'Standard User'
    
    def detect_threat(self, activity, user_id):
        """Detect potential threats from activity"""
        event_id = activity['event_id']
        process = activity['process'].lower()
        details = activity['details']
        
        threat = None
        
        # Event ID 3: Network connection (potential data exfiltration)
        if event_id == '3':
            dest_ip = details.get('DestinationIp', '')
            dest_port = details.get('DestinationPort', '')
            
            # Check for suspicious destinations
            suspicious_ports = ['22', '23', '3389', '5900', '5901']  # SSH, Telnet, RDP, VNC
            suspicious_domains = ['tor', 'vpn', 'proxy', 'anonymous']
            
            if any(port in dest_port for port in suspicious_ports):
                threat = {
                    'user_id': user_id,
                    'type': 'Suspicious Port Connection',
                    'severity': 'medium',
                    'description': f'Connection to suspicious port {dest_port}',
                    'process': activity['process'],
                    'destination': dest_ip,
                    'timestamp': activity['timestamp']
                }
        
        # Event ID 5: Process termination (could be anti-forensics)
        elif event_id == '5':
            if 'sysmon' in process or 'antivirus' in process or 'security' in process:
                threat = {
                    'user_id': user_id,
                    'type': 'Security Process Termination',
                    'severity': 'high',
                    'description': f'Security-related process terminated: {process}',
                    'process': activity['process'],
                    'timestamp': activity['timestamp']
                }
        
        # Check for PowerShell/CMD execution
        elif 'powershell' in process or 'cmd.exe' in process:
            threat = {
                'user_id': user_id,
                'type': 'Command Line Activity',
                'severity': 'low',
                'description': f'Command line process executed: {process}',
                'process': activity['process'],
                'timestamp': activity['timestamp']
            }
        
        return threat
    
    def save_to_redis(self, redis_host='localhost', redis_port=6379):
        """Save extracted users to Redis"""
        try:
            redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
            
            # Save users
            for user_id, user_data in self.users.items():
                redis_client.set(f"user:{user_id}", json.dumps(user_data))
            
            # Save threat indicators
            for i, threat in enumerate(self.threat_indicators):
                redis_client.set(f"threat:{i}", json.dumps(threat))
            
            # Set user list
            redis_client.set("user_list", json.dumps(list(self.users.keys())))
            
            logger.info(f"✅ Saved {len(self.users)} users to Redis")
            logger.info(f"✅ Saved {len(self.threat_indicators)} threats to Redis")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error saving to Redis: {e}")
            return False
    
    def get_users_list(self):
        """Get formatted users list for API"""
        users_list = []
        for user_id, user_data in self.users.items():
            users_list.append({
                'id': user_data['id'],
                'username': user_data['username'],
                'domain': user_data['domain'],
                'full_name': user_data['full_name'],
                'department': user_data['department'],
                'role': user_data['role'],
                'risk_level': user_data['risk_level'],
                'risk_score': user_data['risk_score'],
                'threat_count': user_data['threat_count'],
                'is_service_account': user_data['is_service_account'],
                'process_count': len(user_data['processes']),
                'last_seen': user_data['last_seen']
            })
        
        return sorted(users_list, key=lambda x: x['risk_score'], reverse=True)

if __name__ == "__main__":
    print("="*60)
    print("REAL USER EXTRACTOR FROM SYSMON DATA")
    print("="*60)
    
    extractor = RealUserExtractor("uploaded_sysmon.csv")
    
    if extractor.extract_real_users():
        print(f"\n✅ Extracted {len(extractor.users)} real users:")
        print("-"*60)
        
        for user_id, user_data in extractor.users.items():
            print(f"👤 {user_data['full_name']}")
            print(f"   Department: {user_data['department']}")
            print(f"   Role: {user_data['role']}")
            print(f"   Risk Level: {user_data['risk_level']} (Score: {user_data['risk_score']:.2f})")
            print(f"   Threats Detected: {user_data['threat_count']}")
            print(f"   Processes: {len(user_data['processes'])}")
            print()
        
        print(f"\n🚨 Threat Indicators Detected: {len(extractor.threat_indicators)}")
        
        # Save to Redis
        if extractor.save_to_redis():
            print("✅ Data saved to Redis")
        else:
            print("❌ Failed to save to Redis")
    else:
        print("❌ Failed to extract users from Sysmon data")