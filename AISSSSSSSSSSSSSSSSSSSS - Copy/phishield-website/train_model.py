# train_model.py
import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os

# Define the features (Must match feature_extraction.py order)
FEATURE_COLUMNS = [
    'length_url', 'length_hostname', 'ip', 
    'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 
    'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 
    'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 
    'nb_www', 'nb_com', 'nb_dslash', 
    'http_in_path', 'https_token', 
    'ratio_digits_url', 'ratio_digits_host', 
    'port', 'phish_hints', 
    'shortening_service', 'nb_subdomains', 'prefix_suffix',
    'length_words_raw', 'shortest_word_host', 
    'longest_words_raw', 'longest_word_host', 
    'avg_words_raw', 'avg_word_host', 
    'char_repeat', 
    'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain', 
    'nb_redirection', 'nb_external_redirection', 
    'shortest_word_path', 'longest_word_path', 'avg_word_path'
]

def train():
    dataset_path = 'new_dataset/Training.parquet'
    if not os.path.exists(dataset_path):
        print(f"[ERROR] '{dataset_path}' not found.")
        return

    print("Loading dataset from Parquet...")
    try:
        # Try reading with different engines if needed, defaulting to auto
        try:
            df = pd.read_parquet(dataset_path)
        except:
            df = pd.read_parquet(dataset_path, engine='fastparquet')

        print(f"Dataset loaded. Shape: {df.shape}")
        
        # Check target column
        if 'status' not in df.columns:
            if 'phishing' in df.columns:
                target_col = 'phishing'
            else:
                print("Error: Could not find target column 'status' or 'phishing'")
                print(df.columns)
                return
        else:
            target_col = 'status'

        # Feature Mapping
        # Most names match exactly. We just select them.
        X = df[FEATURE_COLUMNS].copy()
        y = df[target_col]
        
        # Validating target distribution:
        print(f"Target distribution:\n{y.value_counts()}")
        
        # Assuming: legitimate = 0 or -1, phishing = 1
        if y.dtype == 'object':
            y = y.map({'legitimate': 0, 'phishing': 1})
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        print(f"Training Gradient Boosting Classifier (n_estimators=300)...")
        clf = GradientBoostingClassifier(n_estimators=300, learning_rate=0.1, max_depth=5, random_state=42)
        clf.fit(X_train, y_train)
        
        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"[RESULT] Accuracy: {acc*100:.2f}%")
        
        if acc < 0.96:
            print("[WARNING] Accuracy is below 96%. Tuning might be required.")
        else:
            print("[SUCCESS] Accuracy Goal (>96%) Met!")
            
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        # Save model
        with open('model.pkl', 'wb') as f:
            pickle.dump(clf, f)
        print("[INFO] Model saved to 'model.pkl'")

    except Exception as e:
        print(f"[ERROR] Error during training: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    train()
