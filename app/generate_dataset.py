import pandas as pd
import numpy as np
from pathlib import Path

def create_phishing_dataset(n_samples=1000):
    """Create a synthetic dataset for phishing detection"""
    
    # List of example URLs
    safe_urls = [
        'https://www.google.com',
        'https://www.microsoft.com',
        'https://www.github.com',
        'https://www.stackoverflow.com',
        'https://www.python.org',
        'https://www.amazon.com',
        'https://www.facebook.com',
        'https://www.twitter.com',
        'https://www.linkedin.com',
        'https://www.reddit.com'
    ]
    
    phishing_urls = [
        'http://login-secure-bank.xyz',
        'https://verify-paypal-account.net',
        'http://urgent-account-update.com',
        'https://secure-login-amazon.info',
        'http://verify-payment-method.online',
        'http://banking-secure-login.top',
        'https://account-verification-required.xyz',
        'http://secure-banking-update.com',
        'https://verify-account-now.net',
        'http://important-security-update.info'
    ]
    
    # Generate synthetic dataset
    urls = []
    labels = []
    
    # Add variations of safe URLs
    for _ in range(n_samples // 2):
        base_url = np.random.choice(safe_urls)
        if np.random.random() > 0.5:
            # Add some random parameters or paths
            url = f"{base_url}/{''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz'), 5))}"
            if np.random.random() > 0.5:
                url += f"?param={''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), 8))}"
        else:
            url = base_url
        urls.append(url)
        labels.append(0)  # Safe
    
    # Add variations of phishing URLs
    for _ in range(n_samples // 2):
        base_url = np.random.choice(phishing_urls)
        if np.random.random() > 0.5:
            # Add some random parameters or paths
            url = f"{base_url}/{''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz'), 5))}"
            if np.random.random() > 0.5:
                url += f"?param={''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), 8))}"
        else:
            url = base_url
        urls.append(url)
        labels.append(1)  # Phishing
    
    # Create DataFrame
    df = pd.DataFrame({
        'url': urls,
        'label': labels
    })
    
    # Shuffle the dataset
    df = df.sample(frac=1).reset_index(drop=True)
    
    # Create data directory if it doesn't exist
    data_dir = Path('data')
    data_dir.mkdir(exist_ok=True)
    
    # Save dataset
    df.to_csv(data_dir / 'phishing_dataset.csv', index=False)
    print("Dataset created successfully!")
    return df

if __name__ == '__main__':
    create_phishing_dataset()