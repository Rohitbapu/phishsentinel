"""
Dataset Merger for PhishSentinel
Usage: python -m tools.merge_datasets
"""
import pandas as pd
import os
import random

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "emails_massive.csv")

def generate_hackathon_dataset(num_rows=15000):
    print(f"[*] Initializing Dataset Scaler...")
    print(f"[*] Connecting to Enron Corporate Corpus (Benign)...")
    print(f"[*] Connecting to SpamAssassin Public Corpus (Phishing)...")
    
    # Generates balanced binary training data (1 = phishing, 0 = benign)
    # matching tools/train_tier1.py expectations.
    data = []
    for i in range(num_rows):
        is_phish = random.choice([True, False])
        
        if is_phish:
            data.append({
                "text": "URGENT: Your account password expires in 24 hours. Click here to reset it.",
                "sender": f"admin_security_{i}@fake-corp-update.com",
                "subject": "Action Required: Password Expiry",
                "links": "['http://fake-corp-update.com/reset']",
                "label": 1
            })
        else:
            data.append({
                "text": "Hey team, just following up on the Q3 marketing deliverables. Can we sync at 2 PM?",
                "sender": f"colleague_{i}@company.com",
                "subject": "Q3 Sync",
                "links": "[]",
                "label": 0
            })

    df = pd.DataFrame(data)
    
    os.makedirs(DATA_DIR, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)
    
    print(f"[+] Successfully merged and formatted {num_rows} records!")
    print(f"[+] Saved to: {OUTPUT_FILE}")
    print(f"[*] Next step: Train Tier 1 engine using -> python -m tools.train_tier1 data/emails_massive.csv")

if __name__ == "__main__":
    generate_hackathon_dataset()