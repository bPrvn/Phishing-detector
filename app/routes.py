from flask import render_template, request, redirect, url_for
from app import app
import joblib
import os
from ml_model import train_phishing_model, predict_phishing

# Check if the model file exists and delete it before retraining
def delete_existing_model():
    model_path = 'model/phishing_model.pkl'
    if os.path.exists(model_path):
        os.remove(model_path)
        print("Existing model deleted.")

# Route to the main page
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        
        # Check if the model exists, if not, train a new one
        model_path = 'model/phishing_model.pkl'
        if not os.path.exists(model_path):
            print("Training new model...")
            model = train_phishing_model('data/phishing_dataset.csv')  # Train model with the dataset
        else:
            model = joblib.load(model_path)  # Load existing model
        
        result = predict_phishing(url, model)
        is_phishing = result['is_phishing']
        confidence = result['confidence']
        
        return render_template('result.html', is_phishing=is_phishing, confidence=confidence, url=url)
    
    return render_template('index.html')
