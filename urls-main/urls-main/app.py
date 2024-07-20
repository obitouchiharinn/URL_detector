from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from urllib.parse import urlparse
import re
import pandas as pd
import pickle
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# URL data model
class URLData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    prediction = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"URLData('{self.url}', '{self.prediction}', '{self.date}')"

with app.app_context():
    db.create_all()

model_path = 'nammamodel.pkl'
model = pickle.load(open(model_path, 'rb'))

def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    features['url_length'] = len(url)
    features['hostname_length'] = len(parsed_url.netloc)
    features['path_length'] = len(parsed_url.path)
    features['query_length'] = len(parsed_url.query)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_at'] = url.count('@')
    features['num_eq'] = url.count('=')
    features['num_and'] = url.count('&')
    features['num_percent'] = url.count('%')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_letters'] = sum(c.isalpha() for c in url)
    features['num_params'] = len(parsed_url.query.split('&'))
    features['tld_length'] = len(parsed_url.netloc.split('.')[-1])
    features['has_ip'] = 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', parsed_url.netloc) else 0
    features['has_https'] = 1 if parsed_url.scheme == 'https' else 0
    return pd.DataFrame([features])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login')
@login_required
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    url = request.form['url']
    features_df = extract_features(url)
    prediction = model.predict(features_df)[0]
    prediction_proba = model.predict_proba(features_df)[0]

    categories = ['benign', 'defacement', 'malware', 'phishing']
    categories_dict = {'benign': 0, 'defacement': 1, 'malware': 2, 'phishing': 3}
    num = categories_dict[prediction]

    new_url_data = URLData(url=url, prediction=categories[num])
    db.session.add(new_url_data)
    db.session.commit()

    class_probabilities = list(zip(categories, prediction_proba))

    return render_template('index.html', prediction=categories[num], class_probabilities=class_probabilities, url=url)

@app.route('/view_data')
@login_required
def view_data():
    all_urls = URLData.query.all()
    return render_template('view_data.html', urls=all_urls)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
