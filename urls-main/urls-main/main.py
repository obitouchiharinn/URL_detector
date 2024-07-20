import tensorflow as tf
from joblib import load
from urllib.parse import urlparse
import re
import pandas as pd
import pickle

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
    return features


def predict(modelpath,url):
    features=extract_features(url)
    features_df = pd.DataFrame([features])
    
    model=pickle.load(open(modelpath, 'rb'))
    prediction = model.predict(features_df)[0]

    prediction_proba = model.predict_proba(features_df)[0]
    return prediction, prediction_proba

modelpath='nammamodel.pkl'
url="https://t.co/ZrrTHUwKDS?amp=1"

prediction, prediction_proba = predict(modelpath, url)
categories=['benign', 'defacement', 'malware', 'phishing']
categories_dict = {'benign':0, 'defacement':1, 'malware':2, 'phishing':3 }

num= categories_dict[prediction]
print(f"The URL '{url}' is classified as '{categories[num]}' with probabilities: {prediction_proba}")

