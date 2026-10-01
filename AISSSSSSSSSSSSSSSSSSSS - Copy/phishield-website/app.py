from flask import Flask, request, jsonify, send_from_directory
import pickle
import numpy as np
import feature_extraction
import os
import external_api
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='.')

# Load Model
model = None
try:
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("[INFO] Model loaded successfully!")
except FileNotFoundError:
    print("[WARNING] 'model.pkl' not found. Predictions will be simulated/dummy until you run 'train_model.py'.")

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/api/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Extract features
    try:
        features = feature_extraction.extract_features(url)
        
        if model:
            prediction = model.predict(features)[0]
            
            # Handle both string and integer predictions
            if isinstance(prediction, str):
                is_phishing = (prediction.lower() == 'phishing')
            else:
                result = int(prediction)
                is_phishing = (result == 1)
            
            # Calculate Confidence/Probability
            try:
                probs = model.predict_proba(features)
                confidence = int(max(probs[0]) * 100)
            except:
                # Fallback only if model doesn't support probability
                confidence = 100 

            # Prepare structured features for display
            # Mapping based on feature_extraction.py index
            # 0: length_url, 1: length_hostname, 2: ip, 3: nb_dots, 4: nb_hyphens, 
            # 5: nb_at, 6: nb_qm, ... 24: https_token, ... 28: phish_hints, ... 43: nb_redirection, 44: nb_external_redirection
            
            feat_list = features.tolist()[0]
            
            structured_features = [
                {"name": "URL Length", "type": "URL Features", "value": feat_list[0]},
                {"name": "Hostname Length", "type": "URL Features", "value": feat_list[1]},
                {"name": "IP Address Presence", "type": "URL Features", "value": "True" if feat_list[2] == 1 else "False"},
                {"name": "Number of Dots in URL", "type": "URL Features", "value": int(feat_list[3])},
                {"name": "Number of Hyphens in URL", "type": "URL Features", "value": int(feat_list[4])},
                {"name": "Presence of '@' Symbol", "type": "URL Features", "value": "True" if feat_list[5] > 0 else "False"},
                {"name": "Presence of '?' Symbol", "type": "URL Features", "value": "True" if feat_list[6] > 0 else "False"},
                {"name": "HTTPS Presence", "type": "Security Indicators", "value": "True" if feat_list[24] == 1 else "False"},
                {"name": "SSL Certificate Status", "type": "Security Indicators", "value": "Active" if feat_list[24] == 1 else "Inactive"}, # Mapping to HTTPS token
                {"name": "Suspicious Keywords in URL", "type": "Security Indicators", "value": int(feat_list[28])},
                {"name": "Redirect Usage", "type": "Content / Behavior Indicators", "value": "True" if feat_list[43] > 0 else "False"},
                {"name": "External Links Present", "type": "Content / Behavior Indicators", "value": int(feat_list[44])}
            ]

            # External Threat Intelligence Check
            external_result = external_api.check_safe_browsing(url)
            
            # Domain Age Check
            domain_info = external_api.get_domain_creation_info(url)

        else:
            return jsonify({'error': 'Model not loaded. Please restart the server.'}), 500

        return jsonify({
            'is_phishing': is_phishing,
            'result_label': 'Phishing' if is_phishing else 'Legitimate',
            'confidence': confidence,
            'external_threat_intel': external_result,
            'domain_info': domain_info,
            'structured_features': structured_features
        })

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 500

def check_api_auth(request):
    """Verifies that an incoming request has a valid X-API-Key."""
    api_key = request.headers.get("X-API-Key")
    allowed_keys_str = os.environ.get("PUBLIC_API_KEYS", "")
    allowed_keys = [k.strip() for k in allowed_keys_str.split(",") if k.strip()]
    
    # If no keys are configured, fallback to basic demo keys
    if not allowed_keys:
        allowed_keys = ["demokey123", "mysecretkey456"]
        
    return api_key in allowed_keys

@app.route('/api/v1/scan', methods=['POST'])
def public_scan():
    """Public facing, secured endpoint for external applications."""
    if not check_api_auth(request):
        return jsonify({"error": "Unauthorized. Invalid or missing X-API-Key header."}), 401
        
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
        
    try:
        features = feature_extraction.extract_features(url)
        
        if not model:
            return jsonify({'error': 'Model not loaded. Please restart the server.'}), 500
            
        prediction = model.predict(features)[0]
        
        if isinstance(prediction, str):
            is_phishing = (prediction.lower() == 'phishing')
        else:
            result = int(prediction)
            is_phishing = (result == 1)
            
        try:
            probs = model.predict_proba(features)
            confidence = int(max(probs[0]) * 100)
        except:
            confidence = 100 
            
        # Optional: Ask external service as part of the public response
        external_result = external_api.check_safe_browsing(url)
        domain_info = external_api.get_domain_creation_info(url)
        
        # Simplified response specifically for API consumers
        return jsonify({
            'url': url,
            'v1_scan_result': {
                'is_phishing': is_phishing,
                'confidence_score_percent': confidence,
                'domain_info': domain_info,
                'external_threat_intel': external_result
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
