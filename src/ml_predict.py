"""
ml_predict.py
Trains an improved ML model to predict URL types.
"""

from pymongo import MongoClient
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cyber_intel"
COLL_NAME = "urls"

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
col = db[COLL_NAME]

def add_features(df):
    # Additional features
    df['domain_length'] = df['domain'].apply(len)
    df['has_suspicious_words'] = df['url'].str.contains('login|bank|paypal|secure', case=False).astype(int)
    df['entropy'] = df['domain'].apply(lambda x: -sum((x.count(c)/len(x))*np.log2(x.count(c)/len(x)) for c in set(x)) if x else 0)
    return df

def main():
    # Load data
    cursor = col.find({}, {"url_length": 1, "num_subdomains": 1, "has_https": 1, "threat_score": 1, "domain": 1, "url": 1, "type": 1})
    data = list(cursor)
    df = pd.DataFrame(data)
    df['has_https'] = df['has_https'].astype(int)
    df = df.dropna()

    df = add_features(df)
    # Sample smaller dataset for speed
    df = df.sample(n=50000, random_state=42)

    X = df[['url_length', 'num_subdomains', 'has_https', 'threat_score', 'domain_length', 'has_suspicious_words', 'entropy']]
    y = df['type']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Hyperparameter tuning (simplified)
    param_grid = {'n_estimators': [100], 'max_depth': [10]}
    grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=2, scoring='accuracy')
    grid_search.fit(X_train_scaled, y_train)

    model = grid_search.best_estimator_
    print(f"Best Params: {grid_search.best_params_}")

    y_pred = model.predict(X_test_scaled)
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

if __name__ == '__main__':
    main()