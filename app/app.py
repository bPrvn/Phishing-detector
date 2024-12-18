from flask import Flask, render_template, request, redirect, url_for, session, flash
import joblib
import os
from pathlib import Path
from ml_model import train_phishing_model, predict_phishing

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace with a secure secret key

# Constants
MODEL_DIR = Path("model")
MODEL_PATH = MODEL_DIR / "phishing_model.pkl"
DATASET_PATH = Path("data/phishing_dataset.csv")

# Simple user storage (replace with database in production)
users = {}

def ensure_model_exists():
    """Ensure model directory and trained model exist"""
    MODEL_DIR.mkdir(exist_ok=True)
    
    if not MODEL_PATH.exists():
        print("Training new model...")
        model = train_phishing_model(DATASET_PATH)
        return model
    return joblib.load(MODEL_PATH)

@app.route('/')
def index():
    return render_template('index.html', current_user=session.get('user'))

@app.route('/home')
def home():
    return redirect(url_for('index'))  # Redirect /home to the index page

@app.route('/about')
def about():
    return render_template('about.html', current_user=session.get('user'))

@app.route('/contact')
def contact():
    return render_template('contact.html', current_user=session.get('user'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if email in users and users[email]['password'] == password:
            session['user'] = {
                'email': email,
                'username': email.split('@')[0]  # Using email prefix as username
            }
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password')
            return render_template('login.html', error='Invalid email or password')
    
    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirmPassword')
    
    if email in users:
        flash('Email already exists')
        return render_template('login.html', error='Email already exists')
    
    if password != confirm_password:
        flash('Passwords do not match')
        return render_template('login.html', error='Passwords do not match')
    
    users[email] = {
        'password': password,
        'username': email.split('@')[0]
    }
    
    session['user'] = {
        'email': email,
        'username': email.split('@')[0]
    }
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'user' not in session:
        flash('Please login to analyze URLs')
        return redirect(url_for('login'))
    
    url = request.form.get('url')
    if not url:
        flash('Please enter a URL')
        return redirect(url_for('index'))
    
    model = ensure_model_exists()
    result = predict_phishing(url, model)
    
    return render_template('result.html', 
                         is_phishing=result['is_phishing'],
                         confidence=result['confidence'],
                         url=url,
                         current_user=session.get('user'))

if __name__ == '__main__':
    app.run(debug=True)