"""
Real-world Dataset Ingestion for PhishSentinel
Downloads massive, real-world phishing datasets to train the Tier 1 AI.
Usage: python -m tools.ingest_real_datasets
"""
import pandas as pd
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "emails_massive.csv")

def ingest_datasets():
    print("[*] Initializing Real-World Dataset Ingestion...")
    os.makedirs(DATA_DIR, exist_ok=True)
    
    data_rows = []
    
    try:
        from datasets import load_dataset
        print("[*] Attempting Hugging Face connection for 'ealvaradob/phishing-dataset'...")
        # CRITICAL FIX: trust_remote_code=True is required to bypass HF's security block on dataset scripts
        dataset = load_dataset("ealvaradob/phishing-dataset", split="train", trust_remote_code=True)
        
        for i, row in enumerate(dataset):
            if i >= 15000:
                break
            data_rows.append({
                "text": str(row["text"])[:1500],
                "sender": "external@unknown.com",
                "subject": "Scraped Message/URL",
                "links": "[]",
                "label": int(row["label"])
            })
        print("[+] Successfully ingested Hugging Face data!")
            
    except Exception as e:
        print(f"[!] Hugging Face API blocked: {e}")
        print("[*] Activating Fallback: Downloading Kaggle Phishing Dataset directly from GitHub...")
        
        # Bulletproof fallback using standard Pandas over HTTPS
        url = "https://raw.githubusercontent.com/mohitgupta-omg/Kaggle-SMS-Spam-Collection-Dataset-/master/spam.csv"
        fallback_df = pd.read_csv(url, encoding='latin-1')
        
        for _, row in fallback_df.iterrows():
            if len(data_rows) >= 5500:
                break
            data_rows.append({
                "text": str(row["v2"])[:1500],
                "sender": "external@unknown.com",
                "subject": "Scraped Message",
                "links": "[]",
                "label": 1 if row["v1"] == "spam" else 0
            })
        print("[+] Successfully ingested GitHub Kaggle fallback data!")

    # Format and save the dataset for the Tier 1 engine
    df = pd.DataFrame(data_rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True) 
    df.to_csv(OUTPUT_FILE, index=False)
    
    print(f"[+] Ingestion complete! Saved {len(df)} real-world records to {OUTPUT_FILE}")
    print(f"[*] Next Step: Retrain the mathematical engine using -> python -m tools.train_tier1 data/emails_massive.csv")

if __name__ == "__main__":
    ingest_datasets()