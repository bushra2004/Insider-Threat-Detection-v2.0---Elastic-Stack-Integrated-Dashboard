import pandas as pd
import os

def preprocess_logs(input_file="data/combined_logs.csv", output_file="data/processed.csv"):
    if not os.path.exists(input_file):
        print(f"❌ Input file not found: {input_file}")
        return

    # Load logs
    df = pd.read_csv(input_file)

    # Ensure timestamp is datetime if present
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["hour"] = df["timestamp"].dt.hour
        df["is_after_hours"] = df["hour"].apply(lambda x: 1 if (pd.notnull(x) and (x < 9 or x > 18)) else 0)
    else:
        df["is_after_hours"] = 0

    # Failed login feature
    if "status" in df.columns:
        df["failed_login"] = df["status"].apply(lambda x: 1 if str(x).lower() == "failed" else 0)
    else:
        df["failed_login"] = 0

    # Ensure user column exists
    if "user" not in df.columns:
        df["user"] = "unknown"

    # Handle optional columns
    agg_dict = {
        "failed_login": "sum",
        "is_after_hours": "sum"
    }
    if "file" in df.columns:
        agg_dict["file"] = "count"
    if "src_ip" in df.columns:
        agg_dict["src_ip"] = pd.Series.nunique

    # Aggregate features per user
    features = df.groupby("user").agg(agg_dict).reset_index()

    # Rename for consistency
    if "file" in features.columns:
        features.rename(columns={"file": "files_accessed"}, inplace=True)
    else:
        features["files_accessed"] = 0

    if "src_ip" in features.columns:
        features.rename(columns={"src_ip": "unique_ips"}, inplace=True)
    else:
        features["unique_ips"] = 0

    # Save processed file
    features.to_csv(output_file, index=False)
    print(f"✅ Processed data saved to {output_file}")

if __name__ == "__main__":
    preprocess_logs()
