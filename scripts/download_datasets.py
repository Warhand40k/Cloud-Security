#!/usr/bin/env python3
"""
Dataset Downloader and Verification Utility for Cloud Network Anomaly Detection Reproducibility.

This script documents and automates the acquisition of the two public benchmark datasets
evaluated in the research study:
1. UNSW-NB15 (Flow and Windowed telemetry)
2. CSE-CIC-IDS2018 (AWS-hosted Cloud Network Intrusion Detection)

Usage:
    python scripts/download_datasets.py --help
    python scripts/download_datasets.py --verify-only
    python scripts/download_datasets.py --dataset unsw
    python scripts/download_datasets.py --dataset csecicids2018
    python scripts/download_datasets.py --dataset all
"""

import os
import sys
import argparse
import urllib.request
import shutil

RAW_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "raw"))

DATASET_METADATA = {
    "unsw-nb15": {
        "name": "UNSW-NB15",
        "description": "Comprehensive Network Intrusion Detection Benchmark (Flows & Windows)",
        "official_url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "kaggle_url": "https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15",
        "required_files": [
            "UNSW-NB15_1.csv",
            "UNSW-NB15_2.csv",
            "UNSW-NB15_3.csv",
            "UNSW-NB15_4.csv",
            "NUSW-NB15_features.csv",
            "UNSW-NB15_features.csv",
            "UNSW-NB15_LIST_EVENTS.csv",
            "UNSW_NB15_training-set.csv",
            "UNSW_NB15_testing-set.csv",
        ],
        "primary_file_for_experiments": "UNSW-NB15_1.csv",
        "instructions": (
            "Option 1 (Kaggle CLI):\n"
            "    kaggle datasets download -d mrwellsdavid/unsw-nb15 -p data/raw --unzip\n"
            "Option 2 (Direct Download):\n"
            "    Download CSV files from https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15\n"
            "    and place extracted CSVs directly into data/raw/."
        )
    },
    "cse-cic-ids2018": {
        "name": "CSE-CIC-IDS2018",
        "description": "AWS-Hosted Collaborative Network Attack and Penetration Dataset",
        "official_url": "https://www.unb.ca/cic/datasets/ids-2018.html",
        "aws_open_data_url": "https://registry.opendata.aws/cse-cic-ids2018/",
        "s3_bucket": "s3://cse-cic-ids2018/ProcessedTrafficDataStore/",
        "http_base": "https://cse-cic-ids2018.s3.amazonaws.com/ProcessedTrafficDataStore/",
        "evaluated_days": [
            "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
            "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
            "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
        ],
        "instructions": (
            "Option 1 (AWS CLI - no AWS credentials required):\n"
            "    aws s3 cp s3://cse-cic-ids2018/ProcessedTrafficDataStore/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv data/raw/ --no-sign-request\n"
            "    aws s3 cp s3://cse-cic-ids2018/ProcessedTrafficDataStore/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv data/raw/ --no-sign-request\n"
            "    aws s3 cp s3://cse-cic-ids2018/ProcessedTrafficDataStore/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv data/raw/ --no-sign-request\n"
            "Option 2 (Direct HTTPS via curl/wget):\n"
            "    curl -O --output-dir data/raw https://cse-cic-ids2018.s3.amazonaws.com/ProcessedTrafficDataStore/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv\n"
            "    curl -O --output-dir data/raw https://cse-cic-ids2018.s3.amazonaws.com/ProcessedTrafficDataStore/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv\n"
            "    curl -O --output-dir data/raw https://cse-cic-ids2018.s3.amazonaws.com/ProcessedTrafficDataStore/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"
        )
    }
}

def verify_datasets():
    print("=" * 80)
    print("DATASET VERIFICATION & HEALTH CHECK")
    print("=" * 80)
    print(f"Target Directory: {RAW_DIR}\n")
    os.makedirs(RAW_DIR, exist_ok=True)

    # 1. UNSW-NB15
    unsw = DATASET_METADATA["unsw-nb15"]
    print(f"[{unsw['name']}]")
    unsw_found = 0
    for fname in unsw["required_files"]:
        fpath = os.path.join(RAW_DIR, fname)
        if os.path.exists(fpath):
            size_mb = os.path.getsize(fpath) / (1024 * 1024)
            print(f"  [OK] {fname} ({size_mb:.2f} MB)")
            unsw_found += 1
        else:
            print(f"  [MISSING] {fname}")
    print(f"  Status: {unsw_found}/{len(unsw['required_files'])} files detected.\n")

    # 2. CSE-CIC-IDS2018
    cse = DATASET_METADATA["cse-cic-ids2018"]
    print(f"[{cse['name']}]")
    cse_found = 0
    for fname in cse["evaluated_days"]:
        fpath = os.path.join(RAW_DIR, fname)
        if os.path.exists(fpath):
            size_mb = os.path.getsize(fpath) / (1024 * 1024)
            print(f"  [OK] {fname} ({size_mb:.2f} MB)")
            cse_found += 1
        else:
            print(f"  [MISSING] {fname}")
    print(f"  Status: {cse_found}/{len(cse['evaluated_days'])} evaluated days detected.\n")

    if unsw_found == 0 and cse_found == 0:
        print("Note: Raw CSV datasets are not present in data/raw/.")
        print("Refer to download instructions below to fetch them before running raw aggregation.")
        print_instructions()

def print_instructions():
    print("=" * 80)
    print("DOWNLOAD INSTRUCTIONS & DIRECT LINKS")
    print("=" * 80)
    for key, meta in DATASET_METADATA.items():
        print(f"\n--- {meta['name']} ---")
        print(f"Description: {meta['description']}")
        if "official_url" in meta:
            print(f"Official Homepage: {meta['official_url']}")
        if "kaggle_url" in meta:
            print(f"Kaggle Dataset:    {meta['kaggle_url']}")
        if "aws_open_data_url" in meta:
            print(f"AWS Open Data:     {meta['aws_open_data_url']}")
        print("Download Instructions:")
        for line in meta["instructions"].split("\n"):
            print(f"  {line}")

def download_unsw():
    print("\nAttempting automated download of UNSW-NB15 via kagglehub...")
    try:
        import kagglehub
        path = kagglehub.dataset_download("mrwellsdavid/unsw-nb15")
        print(f"Downloaded by kagglehub to: {path}")
        # Symlink or copy
        os.makedirs(RAW_DIR, exist_ok=True)
        for item in os.listdir(path):
            src = os.path.join(path, item)
            dst = os.path.join(RAW_DIR, item)
            if not os.path.exists(dst):
                try:
                    os.symlink(src, dst)
                    print(f"Linked: {item} -> {src}")
                except Exception:
                    shutil.copy2(src, dst)
                    print(f"Copied: {item} to {dst}")
        print("UNSW-NB15 setup complete.")
    except ImportError:
        print("kagglehub package not installed. Please use manual instructions:")
        print(DATASET_METADATA["unsw-nb15"]["instructions"])
    except Exception as e:
        print(f"Download failed: {e}")
        print(DATASET_METADATA["unsw-nb15"]["instructions"])

def download_csecicids2018():
    print("\nAttempting download of CSE-CIC-IDS2018 evaluation days from AWS...")
    os.makedirs(RAW_DIR, exist_ok=True)
    cse = DATASET_METADATA["cse-cic-ids2018"]
    for fname in cse["evaluated_days"]:
        dst = os.path.join(RAW_DIR, fname)
        if os.path.exists(dst):
            print(f"File {fname} already exists in {RAW_DIR}. Skipping.")
            continue
        url = cse["http_base"] + fname
        print(f"Downloading {fname} from {url}...")
        try:
            urllib.request.urlretrieve(url, dst)
            print(f"Successfully downloaded {fname} ({os.path.getsize(dst) / (1024*1024):.2f} MB)")
        except Exception as e:
            print(f"Failed to download {fname}: {e}")
            print(f"Please use AWS CLI command: aws s3 cp {cse['s3_bucket']}{fname} data/raw/ --no-sign-request")

def main():
    parser = argparse.ArgumentParser(description="Dataset Download and Verification Utility")
    parser.add_argument("--verify-only", action="store_true", help="Verify local dataset files and exit")
    parser.add_argument("--instructions", action="store_true", help="Print download links and instructions")
    parser.add_argument("--dataset", choices=["unsw", "csecicids2018", "all"], help="Dataset to download")
    args = parser.parse_args()

    if args.instructions:
        print_instructions()
        return

    if args.verify_only or not args.dataset:
        verify_datasets()
        return

    if args.dataset in ("unsw", "all"):
        download_unsw()
    if args.dataset in ("csecicids2018", "all"):
        download_csecicids2018()

    print("\nFinal Verification:")
    verify_datasets()

if __name__ == "__main__":
    main()
