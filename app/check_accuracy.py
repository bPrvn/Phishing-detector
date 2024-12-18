import pandas as pd
from ml_model import train_phishing_model
from pathlib import Path

def check_model_accuracy():
    print("\n" + "="*50)
    print("PHISHING DETECTION MODEL ACCURACY CHECK")
    print("="*50 + "\n")

    # Load and train model
    data_path = Path("data/phishing_dataset.csv")
    
    # Show dataset information
    df = pd.read_csv(data_path)
    print("Dataset Information:")
    print(f"Total URLs in dataset: {len(df)}")
    print(f"Safe URLs: {len(df[df['label'] == 0])}")
    print(f"Phishing URLs: {len(df[df['label'] == 1])}")
    
    print("\nTraining model and calculating accuracy...\n")
    model = train_phishing_model(data_path)
    
    # Test some sample URLs
    test_urls = [
        "https://www.google.com",
        "https://www.microsoft.com",
        "http://suspicious-bank-login.xyz",
        "http://verify-account-secure.net"
    ]
    
    print("\nTesting sample URLs:")
    for url in test_urls:
        result = model.predict_proba([url])[0]
        confidence = result[1] if result[1] > result[0] else 1 - result[1]
        is_phishing = result[1] > 0.5
        print(f"\nURL: {url}")
        print(f"Detection: {'Phishing' if is_phishing else 'Safe'}")
        print(f"Confidence: {confidence*100:.2f}%")

if __name__ == "__main__":
    check_model_accuracy()