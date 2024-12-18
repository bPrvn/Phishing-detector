import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import joblib
from pathlib import Path
from ml_model import train_phishing_model, predict_phishing
from datetime import datetime

# Get absolute path to static folder
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

app = Flask(__name__, 
           static_folder=static_dir,
           static_url_path='/static')
app.secret_key = 'your-secret-key-here'

# Constants
MODEL_DIR = Path("model")
MODEL_PATH = MODEL_DIR / "phishing_model.pkl"
DATASET_PATH = Path("data/phishing_dataset.csv")

def ensure_model_exists():
    """Ensure model directory and trained model exist"""
    MODEL_DIR.mkdir(exist_ok=True)
    
    if not MODEL_PATH.exists():
        print("\n=== Training New Model ===")
        model = train_phishing_model(DATASET_PATH)
        return model
    return joblib.load(MODEL_PATH)

# Optional: Add direct route for images
@app.route('/static/images/<path:filename>')
def serve_image(filename):
    return send_from_directory(os.path.join(static_dir, 'images'), filename)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if request.method == 'POST':
        url = request.form['url']
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Ensure model exists and predict
            model = ensure_model_exists()
            result = predict_phishing(url, model)
            
            return render_template('result.html', 
                                 url=url,
                                 is_phishing=result['is_phishing'],
                                 confidence=result['confidence'],
                                 current_time=current_time)
        except Exception as e:
            print(f"Error during analysis: {e}")
            return render_template('result.html', 
                                 url=url,
                                 is_phishing=True,
                                 confidence=1.0,
                                 current_time=current_time,
                                 error="An error occurred during analysis")
    
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if email and password:
            session['user_email'] = email
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error="Please enter both email and password")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=True)