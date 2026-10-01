import pickle
import numpy as np
import feature_extraction
import sys

def verify():
    print("Verifying setup...")
    
    # Test Feature Extraction
    url = "http://google.com"
    try:
        features = feature_extraction.extract_features(url)
        print(f"[SUCCESS] Feature extraction worked. Shape: {features.shape}")
    except Exception as e:
        print(f"[ERROR] Feature extraction failed: {e}")
        return

    # Test Model Loading
    try:
        with open('model.pkl', 'rb') as f:
            model = pickle.load(f)
        print("[SUCCESS] Model loaded successfully.")
    except Exception as e:
        print(f"[ERROR] Model loading failed: {e}")
        print("Suggestion: Run 'python train_model.py' to retrain the model with current dependencies.")
        return

    # Test Prediction
    try:
        prediction = model.predict(features)[0]
        probs = model.predict_proba(features)[0]
        print(f"[SUCCESS] Prediction: {prediction}, Probs: {probs}")
    except Exception as e:
        print(f"[ERROR] Prediction failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    verify()
