# PHISHIED - Advanced Phishing Detection

PHISHIED is a machine learning-powered web application for detecting phishing websites. It uses advanced lexical feature extraction and a Gradient Boosting model to analyze URLs in real-time.

## Features
- **Real-time Analysis**: Extracts 47 lexical features from any URL.
- **High Accuracy**: Uses a trained Gradient Boosting Classifier (~90% accuracy).
- **Web Interface**: Simple, responsive UI for easy testing.

## Prerequisites
- Python 3.8+
- Dependencies: `flask`, `pandas`, `numpy`, `scikit-learn`, `fastparquet`

## Setup & Run

1.  **Clone/Navigate** to the project directory:
  
   <!-- cd "c:/ais v2/AIS/phishied-website" -->
  

2.  **Install Dependencies**:
    
    <!-- pip install flask pandas numpy scikit-learn fastparquet -->
   

3.  **Run the Application**:
  
    <!-- python app.py -->
    

4.  **Access**:
    Open [http://localhost:5000](http://localhost:5000) in your browser.

## Model Training
To retrain the model with the latest dataset:

<!-- python train_model.py -->
**avisham ondel mathi 

This will generate a new `model.pkl`.