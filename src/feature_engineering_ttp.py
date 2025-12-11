# src/feature_engineering_ttp.py
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re

# Define lists of suspicious indicators (these should be expanded in a real system)
SUSPICIOUS_PARENT_CHAINS = [
    ('outlook.exe', 'powershell.exe'),
    ('chrome.exe', 'cmd.exe'),
    ('winword.exe', 'wscript.exe'),
    ('excel.exe', 'powershell.exe'),
]
SUSPICIOUS_CMDLINE_FLAGS = [
    r'-enc\b', r'-ec\b', r'\/c\b', r'wget.*\-O', r'curl.*\-o', 
    r'iex\s*\(', r'invoke-expression', r'hidden', r'\-windowstyle\shidden'
]
KNOWN_GOOD_DOMAINS = {'microsoft.com', 'google.com', 'windowsupdate.com', 'apple.com'} # Example list
DYNAMIC_DNS_DOMAINS = {'duckdns.org', 'no-ip.com', 'dynDNS.com'} # Example list

def add_ttp_features(df):
    """
    Adds MITRE ATT&CK TTP-based features to the DataFrame.
    Assumes the DataFrame has columns like 'EventID', 'ParentImage', 'Image', 'CommandLine', 'DestinationIp', 'TargetFilename', etc.
    """
    # Make a copy to avoid SettingWithCopyWarning
    df_enhanced = df.copy()
    
    # --- T1059 - Command & Scripting Interpreter ---
    # Feature: Suspicious parent-child process chain
    df_enhanced['ttp_T1059_suspicious_chain'] = False
    for parent, child in SUSPICIOUS_PARENT_CHAINS:
        mask = (df_enhanced['ParentImage'].str.contains(parent, case=False, na=False)) & \
               (df_enhanced['Image'].str.contains(child, case=False, na=False))
        df_enhanced.loc[mask, 'ttp_T1059_suspicious_chain'] = True

    # Feature: Suspicious command-line flags
    df_enhanced['ttp_T1059_suspicious_cmd'] = df_enhanced['CommandLine'].str.contains(
        '|'.join(SUSPICIOUS_CMDLINE_FLAGS), 
        case=False, 
        na=False, 
        regex=True
    )

    # --- T1036 - Masquerading ---
    # Feature: Process name anomaly (e.g., lsass.exe not in system32)
    df_enhanced['ttp_T1036_masquerading'] = False
    system_processes = ['lsass.exe', 'svchost.exe', 'smss.exe']
    for proc in system_processes:
        # Check if process name matches but path is not in Windows system directories
        mask = (df_enhanced['Image'].str.endswith(proc, na=False)) & \
               (~df_enhanced['Image'].str.contains(r'C:\\Windows\\System32', case=False, na=False))
        df_enhanced.loc[mask, 'ttp_T1036_masquerading'] = True

    # --- T1048 - Exfiltration ---
    # Feature: Large data upload (placeholder logic - needs scaling)
    if 'SentBytes' in df_enhanced.columns:
        df_enhanced['SentBytes'] = pd.to_numeric(df_enhanced['SentBytes'], errors='coerce').fillna(0)
        # Calculate a simple z-score for sent bytes per process name
        mean_sent = df_enhanced.groupby('Image')['SentBytes'].transform('mean')
        std_sent = df_enhanced.groupby('Image')['SentBytes'].transform('std')
        df_enhanced['ttp_T1048_large_upload'] = (df_enhanced['SentBytes'] - mean_sent) / (std_sent + 1e-6) > 3 # > 3 std devs

    # Feature: Connection to rare or dynamic DNS domain
    df_enhanced['ttp_T1048_rare_domain'] = False
    if 'DestinationHostname' in df_enhanced.columns:
        # Extract domain from hostname
        df_enhanced['domain'] = df_enhanced['DestinationHostname'].apply(
            lambda x: '.'.join(urlparse('//' + str(x)).hostname.split('.')[-2:]) if pd.notna(x) else None
        )
        # Mark if domain is not in known-good list or is a dynamic DNS domain
        df_enhanced['ttp_T1048_rare_domain'] = ~df_enhanced['domain'].isin(KNOWN_GOOD_DOMAINS) | \
                                              df_enhanced['domain'].isin(DYNAMIC_DNS_DOMAINS)

    # --- T1005 - Data from Local System ---
    # Feature: Access to sensitive files
    sensitive_paths = [r'\\SAM$', r'\\SECURITY$', r'\\Credentials\\', r'\\Login Data$', r'\\History$']
    regex_pattern = '|'.join(sensitive_paths)
    if 'TargetFilename' in df_enhanced.columns:
        df_enhanced['ttp_T1005_sensitive_file_access'] = df_enhanced['TargetFilename'].str.contains(
            regex_pattern, case=False, na=False, regex=True
        )

    print(f"[INFO] Added {sum(col.startswith('ttp_') for col in df_enhanced.columns)} new TTP-based features.")
    return df_enhanced