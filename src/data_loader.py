import os
import ssl
import json
import urllib.request
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import pandas as pd
import numpy as np
import certifi

import config
from src.database import get_db_connection, log_audit

# Verified authentic benchmark URLs
NSL_KDD_URLS = {
    "train_20": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B_20Percent.txt",
    "train_full": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt",
    "test_full": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"
}

def download_nsl_kdd(use_20_percent: bool = True) -> Tuple[Path, Path]:
    """
    Downloads authentic NSL-KDD benchmark training and test datasets.
    Uses verified CA bundle from certifi.
    """
    ctx = ssl.create_default_context(cafile=certifi.where())
    train_key = "train_20" if use_20_percent else "train_full"
    train_url = NSL_KDD_URLS[train_key]
    test_url = NSL_KDD_URLS["test_full"]

    train_filename = "KDDTrain+_20Percent.csv" if use_20_percent else "KDDTrain+.csv"
    train_path = config.DATA_RAW_DIR / train_filename
    test_path = config.DATA_RAW_DIR / "KDDTest+.csv"

    # Download Train
    if not train_path.exists():
        print(f"Downloading NSL-KDD train dataset from {train_url}...")
        req = urllib.request.Request(train_url, headers={"User-Agent": "AcademicSOC-Downloader/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp, open(train_path, "wb") as f:
            f.write(resp.read())
        print(f"Downloaded train dataset to {train_path} ({train_path.stat().st_size} bytes)")

    # Download Test
    if not test_path.exists():
        print(f"Downloading NSL-KDD test dataset from {test_url}...")
        req = urllib.request.Request(test_url, headers={"User-Agent": "AcademicSOC-Downloader/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp, open(test_path, "wb") as f:
            f.write(resp.read())
        print(f"Downloaded test dataset to {test_path} ({test_path.stat().st_size} bytes)")

    return train_path, test_path

def load_nsl_kdd(file_path: Path) -> pd.DataFrame:
    """Loads NSL-KDD format data and assigns standardized column headers."""
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset file not found at: {file_path}")

    # NSL-KDD has 43 columns without headers in raw .txt files
    df = pd.read_csv(file_path, header=None, names=config.NSL_KDD_COLUMNS)
    return df

def generate_synthetic_dataset(output_path: Path, num_records: int = 500) -> Path:
    """
    Generates a small synthetic flow dataset explicitly labelled for offline interface validation.
    Does NOT substitute for real experimental evaluation.
    """
    np.random.seed(42)
    protocols = ["tcp", "udp", "icmp"]
    services = ["http", "smtp", "ftp", "ssh", "dns", "other"]
    flags = ["SF", "S0", "REJ", "RSTO", "SH"]
    labels = ["normal"] * int(num_records * 0.6) + \
             ["neptune"] * int(num_records * 0.2) + \
             ["satan"] * int(num_records * 0.1) + \
             ["guess_passwd"] * int(num_records * 0.08) + \
             ["buffer_overflow"] * int(num_records * 0.02)

    # Pad or truncate to exact num_records
    if len(labels) < num_records:
        labels += ["normal"] * (num_records - len(labels))
    labels = labels[:num_records]
    np.random.shuffle(labels)

    data = {
        "duration": np.random.exponential(scale=2.0, size=num_records).round(2),
        "protocol_type": np.random.choice(protocols, size=num_records),
        "service": np.random.choice(services, size=num_records),
        "flag": np.random.choice(flags, size=num_records),
        "src_bytes": np.random.randint(0, 50000, size=num_records),
        "dst_bytes": np.random.randint(0, 100000, size=num_records),
        "land": np.zeros(num_records, dtype=int),
        "wrong_fragment": np.random.choice([0, 1, 3], size=num_records, p=[0.98, 0.01, 0.01]),
        "urgent": np.zeros(num_records, dtype=int),
        "hot": np.random.choice([0, 1, 2], size=num_records, p=[0.95, 0.03, 0.02]),
        "num_failed_logins": np.random.choice([0, 1, 3], size=num_records, p=[0.97, 0.02, 0.01]),
        "logged_in": np.random.choice([0, 1], size=num_records, p=[0.4, 0.6]),
        "num_compromised": np.random.choice([0, 1], size=num_records, p=[0.98, 0.02]),
        "root_shell": np.zeros(num_records, dtype=int),
        "su_attempted": np.zeros(num_records, dtype=int),
        "num_root": np.zeros(num_records, dtype=int),
        "num_file_creations": np.zeros(num_records, dtype=int),
        "num_shells": np.zeros(num_records, dtype=int),
        "num_access_files": np.zeros(num_records, dtype=int),
        "num_outbound_cmds": np.zeros(num_records, dtype=int),
        "is_host_login": np.zeros(num_records, dtype=int),
        "is_guest_login": np.zeros(num_records, dtype=int),
        "count": np.random.randint(1, 512, size=num_records),
        "srv_count": np.random.randint(1, 512, size=num_records),
        "serror_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "srv_serror_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "rerror_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "srv_rerror_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "same_srv_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "diff_srv_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "srv_diff_host_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "dst_host_count": np.random.randint(0, 255, size=num_records),
        "dst_host_srv_count": np.random.randint(0, 255, size=num_records),
        "dst_host_same_srv_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "dst_host_diff_srv_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "dst_host_same_src_port_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "dst_host_srv_diff_host_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "dst_host_serror_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "dst_host_srv_serror_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "dst_host_rerror_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "dst_host_srv_rerror_rate": np.random.uniform(0.0, 1.0, size=num_records).round(2),
        "label": labels,
        "difficulty_level": np.random.randint(1, 21, size=num_records)
    }
    df = pd.DataFrame(data)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Generated synthetic verification dataset ({num_records} rows) at: {output_path}")
    return output_path
