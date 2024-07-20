import pandas as pd
import numpy as np
import re
import pickle
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Function to extract features from URLs
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

# Load the dataset (assuming a CSV file with 'url' and 'label' columns)
data = pd.read_csv('data2.csv')

# Apply feature extraction
feature_list = data['url'].apply(extract_features)
features_df = pd.DataFrame(feature_list.tolist())

# Combine features with the labels
features_df['type'] = data['type']

# Split the data into features and target variable
X = features_df.drop('type', axis=1)
y = features_df['type']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize the model
model = RandomForestClassifier(n_estimators=1000, random_state=42, max_features='sqrt')

# Train the model
model.fit(X_train, y_train)

# from joblib import dump
# dump(model, 'ourmodel.joblib')
# print("Dump done")
pickle.dump(model, open('nammamodel.pkl', 'wb'))

# Predict on the test set
y_pred = model.predict(X_test)

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy}")

# Classification report
print(classification_report(y_test, y_pred, target_names=['benign', 'defacement', 'malware', 'phishing']))

# Confusion matrix
conf_matrix = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(conf_matrix)
