import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score
import joblib
import re
import urllib.parse
from urllib.parse import urlparse
from tld import get_tld
from pathlib import Path

def extract_advanced_features(url):
    """Extract comprehensive features from URL for enhanced phishing detection"""
    try:
        parsed = urlparse(url)
        tld_info = get_tld(url, as_object=True, fail_silently=True)
        domain = tld_info.domain if tld_info else parsed.netloc
        
        features = {
            # Length-based features
            'url_length': len(url),
            'domain_length': len(domain),
            'path_length': len(parsed.path),
            
            # Domain-based features
            'has_ip': bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)),
            'has_at_symbol': '@' in url,
            'has_double_slash': url.count('//') > 1,
            'has_dash_in_domain': '-' in domain,
            'has_https': url.startswith('https://'),
            
            # Advanced security features
            'subdomain_count': len(domain.split('.')) - 1,
            'domain_registration_length': len(domain),
            'has_sensitive_words': any(word in url.lower() for word in [
                'secure', 'account', 'update', 'banking', 'login', 'verify',
                'signin', 'payment', 'confirm', 'password', 'credential'
            ]),
            
            # Suspicious elements
            'suspicious_tlds': any(tld in url.lower() for tld in [
                '.zip', '.exe', '.bat', '.scr', '.bid', '.party', '.top', '.xyz',
                '.club', '.gq', '.ml', '.cf', '.tk', '.pw', '.cc', '.center',
                '.work', '.live', '.world', '.link'
            ]),
            
            # URL composition features
            'digit_count': sum(c.isdigit() for c in url),
            'letter_count': sum(c.isalpha() for c in url),
            'special_char_count': sum(not c.isalnum() for c in url),
            'directory_count': len([x for x in parsed.path.split('/') if x]),
            'param_count': len(parsed.query.split('&')) if parsed.query else 0,
            
            # Ratio-based features
            'digit_ratio': sum(c.isdigit() for c in url) / len(url) if url else 0,
            'letter_ratio': sum(c.isalpha() for c in url) / len(url) if url else 0,
            'special_char_ratio': sum(not c.isalnum() for c in url) / len(url) if url else 0
        }
        return features
    except Exception as e:
        print(f"Error extracting features from URL: {e}")
        return None

def preprocess_data(data):
    """Preprocess URL data and extract features"""
    features = []
    for url in data['url']:
        url_features = extract_advanced_features(url)
        if url_features:
            features.append(url_features)
        else:
            features.append({k: 0 for k in extract_advanced_features("https://example.com").keys()})
    
    return pd.DataFrame(features)

def train_phishing_model(data_path):
    """Train an enhanced phishing detection model"""
    print("\n")
    print("*" * 50)
    print("PHISHING DETECTION MODEL TRAINING")
    print("*" * 50)
    
    print("\nLoading dataset...")
    data = pd.read_csv(data_path)
    
    print("\nExtracting features from URLs...")
    X_features = preprocess_data(data)
    X_text = data['url']
    y = data['label']
    
    # Split data
    print("\nSplitting dataset into training and testing sets...")
    X_features_train, X_features_test, X_text_train, X_text_test, y_train, y_test = train_test_split(
        X_features, X_text, y, test_size=0.2, random_state=42
    )
    
    print("\nTraining model...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            analyzer='char_wb'
        )),
        ('scaler', StandardScaler(with_mean=False)),
        ('classifier', GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            subsample=0.8,
            random_state=42
        ))
    ])
    
    pipeline.fit(X_text_train, y_train)
    
    # Calculate and print metrics
    train_score = pipeline.score(X_text_train, y_train)
    test_score = pipeline.score(X_text_test, y_test)
    
    print("\n" + "=" * 50)
    print("MODEL PERFORMANCE METRICS")
    print("=" * 50)
    print(f"Training Accuracy: {train_score*100:.2f}%")
    print(f"Testing Accuracy: {test_score*100:.2f}%")
    print(f"Total URLs analyzed: {len(data)}")
    print("=" * 50 + "\n")
    
    # Save model
    MODEL_DIR = Path("model")
    MODEL_DIR.mkdir(exist_ok=True)
    MODEL_PATH = MODEL_DIR / "phishing_model.pkl"
    joblib.dump(pipeline, MODEL_PATH)
    
    return pipeline

def predict_phishing(url, model):
    """Predict if URL is phishing with enhanced confidence calculation"""
    try:
        prediction = model.predict([url])[0]
        proba = model.predict_proba([url])[0]
        
        # Enhanced confidence calculation
        if prediction == 1:  # Phishing
            confidence = proba[1]
        else:
            confidence = proba[0]
            
        return {
            'is_phishing': bool(prediction),
            'confidence': float(confidence)
        }
    except Exception as e:
        print(f"Error predicting URL: {e}")
        return {
            'is_phishing': True,
            'confidence': 1.0
        }