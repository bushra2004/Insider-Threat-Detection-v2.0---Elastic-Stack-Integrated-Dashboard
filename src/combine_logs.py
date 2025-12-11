# src/combine_logs.py
import pandas as pd
import os

def integrate_logs():
    data_dir = "data"
    output_file = os.path.join(data_dir, "combined_logs.csv")

    logs = []

    # ✅ 1. Sysmon logs
    sysmon_file = os.path.join(data_dir, "sysmon_logs.csv")
    if os.path.exists(sysmon_file):
        try:
            sysmon = pd.read_csv(sysmon_file, encoding="utf-8", on_bad_lines="skip")
            # normalize columns
            sysmon = sysmon.rename(columns={
                "TimeCreated": "timestamp",
                "EventID": "event_id",
                "Provider_Name": "provider",
                "Message": "message"
            })
            sysmon["source"] = "sysmon"
            logs.append(sysmon)
            print(f"✅ Loaded {len(sysmon)} Sysmon events")
        except Exception as e:
            print(f"⚠️ Error loading sysmon logs: {e}")

    # ✅ 2. Authentication logs (if you already have)
    cred_file = os.path.join(data_dir, "auth_logs.csv")
    if os.path.exists(cred_file):
        try:
            creds = pd.read_csv(cred_file)
            creds["source"] = "auth"
            logs.append(creds)
            print(f"✅ Loaded {len(creds)} auth log entries")
        except Exception as e:
            print(f"⚠️ Error loading auth logs: {e}")

    # ✅ 3. Other logs you may add later
    # Example: network_logs.csv, file_access.csv etc.
    other_logs = ["network_logs.csv", "file_access.csv"]
    for file in other_logs:
        path = os.path.join(data_dir, file)
        if os.path.exists(path):
            try:
                df = pd.read_csv(path)
                df["source"] = file.replace(".csv", "")
                logs.append(df)
                print(f"✅ Loaded {len(df)} entries from {file}")
            except Exception as e:
                print(f"⚠️ Error loading {file}: {e}")

    # ✅ Merge all logs
    if logs:
        combined = pd.concat(logs, ignore_index=True, sort=False)
        combined.to_csv(output_file, index=False)
        print(f"\n🎯 Combined logs saved to {output_file} with {len(combined)} total entries")
    else:
        print("⚠️ No logs found to combine!")

if __name__ == "__main__":
    integrate_logs()
