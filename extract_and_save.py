# extract_and_save.py - Extract Sysmon users and save to JSON
import json
import pandas as pd
from datetime import datetime

print("="*60)
print("EXTRACTING REAL USERS FROM SYSMON")
print("="*60)

try:
    from sysmon_user_extractor import RealUserExtractor
    
    # Extract users
    extractor = RealUserExtractor("uploaded_sysmon.csv")
    if extractor.extract_real_users():
        users = extractor.get_users_list()
        threats = extractor.threat_indicators
        
        print(f"✅ Successfully extracted {len(users)} real users")
        
        # Save to JSON
        data = {
            'users': users,
            'threats': threats,
            'total_users': len(users),
            'total_threats': len(threats),
            'extracted_at': datetime.now().isoformat(),
            'source_file': 'uploaded_sysmon.csv'
        }
        
        with open('sysmon_users.json', 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✅ Saved to sysmon_users.json")
        
        # Also save to CSV for easy viewing
        if users:
            df = pd.DataFrame(users)
            df.to_csv('sysmon_users.csv', index=False)
            print(f"✅ Saved to sysmon_users.csv")
            
            # Display the users
            print("\n👥 EXTRACTED USERS:")
            print("-"*40)
            for user in users:
                print(f"• {user.get('full_name', 'Unknown')}")
                print(f"  Department: {user.get('department', 'Unknown')}")
                print(f"  Risk Level: {user.get('risk_level', 'Unknown')}")
                print(f"  Risk Score: {user.get('risk_score', 0):.2f}")
                print()
        
        if threats:
            print(f"🚨 DETECTED THREATS: {len(threats)}")
            for threat in threats[:5]:  # Show first 5
                print(f"• {threat.get('type', 'Unknown')} - {threat.get('severity', 'Unknown')}")
        else:
            print("✅ No threats detected")
            
    else:
        print("❌ Failed to extract users from Sysmon data")
        
except ImportError as e:
    print(f"❌ Error: {e}")
    print("Make sure sysmon_user_extractor.py is in the same directory")
except Exception as e:
    print(f"❌ Unexpected error: {e}")