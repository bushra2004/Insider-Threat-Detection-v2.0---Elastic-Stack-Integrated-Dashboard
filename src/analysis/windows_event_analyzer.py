# src/analysis/windows_event_analyzer.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta, date
import json
import matplotlib.pyplot as plt
import os

class WindowsEventAnalyzer:
    def __init__(self):
        self.events = []
    
    def generate_sample_events(self, num_events=100):
        """Generate sample Windows event log data"""
        print("Generating sample Windows event data...")
        
        event_templates = [
            {'event_id': 4624, 'type': 'Audit Success', 'source': 'Microsoft-Windows-Security-Auditing', 
             'message': 'An account was successfully logged on.'},
            {'event_id': 4625, 'type': 'Audit Failure', 'source': 'Microsoft-Windows-Security-Auditing', 
             'message': 'An account failed to log on.'},
            {'event_id': 4634, 'type': 'Audit Success', 'source': 'Microsoft-Windows-Security-Auditing', 
             'message': 'An account was logged off.'},
            {'event_id': 4648, 'type': 'Audit Success', 'source': 'Microsoft-Windows-Security-Auditing', 
             'message': 'A logon was attempted using explicit credentials.'},
            {'event_id': 4672, 'type': 'Audit Success', 'source': 'Microsoft-Windows-Security-Auditing', 
             'message': 'Special privileges assigned to new logon.'},
            {'event_id': 4688, 'type': 'Audit Success', 'source': 'Microsoft-Windows-Security-Auditing', 
             'message': 'A new process has been created.'},
            {'event_id': 4700, 'type': 'Audit Success', 'source': 'Microsoft-Windows-Security-Auditing', 
             'message': 'A scheduled task was enabled.'},
            {'event_id': 4719, 'type': 'Audit Success', 'source': 'Microsoft-Windows-Security-Auditing', 
             'message': 'System audit policy was changed.'}
        ]
        
        users = ['admin', 'john.doe', 'jane.smith', 'svc_backup', 'system']
        computers = ['WORKSTATION-01', 'SERVER-01', 'LAPTOP-05', 'DESKTOP-12']
        
        events = []
        for i in range(num_events):
            template = event_templates[i % len(event_templates)]
            user = users[i % len(users)]
            computer = computers[i % len(computers)]
            
            events.append({
                'timestamp': (datetime.now() - timedelta(minutes=i*10)).strftime('%Y-%m-%d %H:%M:%S'),
                'event_id': template['event_id'],
                'event_type': template['type'],
                'source': template['source'],
                'computer': computer,
                'message': template['message'] + f' Account: {user} Computer: {computer}'
            })
        
        # Add some suspicious events
        for i in range(5):
            events.append({
                'timestamp': (datetime.now() - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'),
                'event_id': 4625,
                'event_type': 'Audit Failure',
                'source': 'Microsoft-Windows-Security-Auditing',
                'computer': 'WORKSTATION-01',
                'message': f'An account failed to log on. Account: admin Computer: WORKSTATION-01 Error: 0xC0000064'
            })
        
        self.events = events
        return events
    
    def detect_suspicious_activity(self):
        """Detect suspicious activity in event logs"""
        if not self.events:
            return []
        
        df = pd.DataFrame(self.events)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        suspicious_events = []
        
        # Detect multiple failed logins
        failed_logins = df[df['event_id'] == 4625].copy()  # Use .copy() to avoid SettingWithCopyWarning
        if not failed_logins.empty:
            # Group by 1-hour windows and count failures
            failed_logins.loc[:, 'hour_window'] = failed_logins['timestamp'].dt.floor('h')  # Use 'h' instead of 'H'
            failure_counts = failed_logins.groupby(['hour_window', 'computer']).size()
            
            for (timestamp, computer), count in failure_counts.items():
                if count > 3:  # More than 3 failures in an hour
                    suspicious_events.append({
                        'type': 'Multiple Failed Logins',
                        'timestamp': timestamp.isoformat(),  # Convert to string for JSON
                        'count': count,
                        'target': computer,
                        'message': f'{count} failed login attempts on {computer}',
                        'severity': 'High'
                    })
        
        # Detect after-hours activity (10 PM to 6 AM)
        df_copy = df.copy()  # Work on a copy to avoid warnings
        df_copy.loc[:, 'hour'] = df_copy['timestamp'].dt.hour
        after_hours = df_copy[df_copy['hour'].between(22, 23) | df_copy['hour'].between(0, 6)].copy()
        
        if not after_hours.empty:
            # Count after-hours events by day and type
            after_hours.loc[:, 'date'] = after_hours['timestamp'].dt.date
            after_hours_counts = after_hours.groupby(['date', 'event_type']).size()
            
            for (date, event_type), count in after_hours_counts.items():
                if count > 2:  # More than 2 events of same type in one night
                    suspicious_events.append({
                        'type': 'After-Hours Activity',
                        'timestamp': datetime.combine(date, datetime.min.time()).isoformat(),
                        'count': count,
                        'target': event_type,
                        'message': f'{count} {event_type} events during off-hours on {date}',
                        'severity': 'Medium'
                    })
        
        # Detect privilege escalation events
        privilege_events = df[df['event_id'].isin([4672, 4688])].copy()
        if not privilege_events.empty:
            # Look for privilege events outside normal hours or unusual patterns
            privilege_events.loc[:, 'hour'] = privilege_events['timestamp'].dt.hour
            unusual_privilege = privilege_events[privilege_events['hour'].between(20, 6)]
            
            for _, event in unusual_privilege.iterrows():
                suspicious_events.append({
                    'type': 'Unusual Privilege Event',
                    'timestamp': event['timestamp'].isoformat(),
                    'count': 1,
                    'target': event['computer'],
                    'message': f'Privilege event during unusual hours: {event["message"]}',
                    'severity': 'High'
                })
        
        return suspicious_events

def generate_event_report(events, suspicious_activities):
    """Generate event log analysis report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create output directory if it doesn't exist
    os.makedirs('../output/reports', exist_ok=True)
    os.makedirs('../output/screenshots', exist_ok=True)
    
    # Save events to CSV
    if events:
        events_df = pd.DataFrame(events)
        events_file = f"../output/reports/windows_events_{timestamp}.csv"
        events_df.to_csv(events_file, index=False)
    
    # Create summary report - ensure all datetime objects are converted to strings
    report = {
        "scan_time": timestamp,
        "total_events": len(events),
        "suspicious_activities_count": len(suspicious_activities),
        "suspicious_activities": suspicious_activities,  # Already converted to strings
        "events_file": events_file if events else None
    }
    
    # Save report
    report_file = f"../output/reports/event_analysis_{timestamp}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=4, default=str)  # Use default=str to handle any non-serializable objects
    
    # Generate visualization
    if events:
        plt.figure(figsize=(12, 6))
        
        events_df = pd.DataFrame(events)
        event_counts = events_df['event_type'].value_counts()
        
        plt.bar(event_counts.index, event_counts.values)
        plt.title('Windows Event Log Distribution')
        plt.xlabel('Event Type')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        plot_file = f"../output/screenshots/event_analysis_{timestamp}.png"
        plt.savefig(plot_file)
        report['plot_file'] = plot_file
    
    return report_file

if __name__ == "__main__":
    analyzer = WindowsEventAnalyzer()
    
    print("Generating sample Windows event data...")
    events = analyzer.generate_sample_events(100)
    
    print("Analyzing for suspicious activity...")
    suspicious_activities = analyzer.detect_suspicious_activity()
    
    report_file = generate_event_report(events, suspicious_activities)
    
    print(f"Generated {len(events)} sample events")
    print(f"Found {len(suspicious_activities)} suspicious activities")
    print(f"Report saved to {report_file}")
    
    # Display some suspicious activities
    if suspicious_activities:
        print("\nSuspicious Activities Found:")
        for activity in suspicious_activities[:5]:  # Show first 5
            print(f"- {activity['type']}: {activity['message']} (Severity: {activity['severity']})")
    else:
        print("\nNo suspicious activities found.")