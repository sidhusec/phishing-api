from flask import Flask, request, jsonify
import pickle
import numpy as np
import pandas as pd

# 🔹 Step 1: Load the trained model
with open("phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

# 🔹 Step 2: Initialize Flask app
app = Flask(__name__)

# 🔹 Step 3: Define feature extraction function
def extract_features(data):
    """Convert input JSON to feature DataFrame (match model's training data)"""
    df = pd.DataFrame([data])
    
    # Ensure the same feature columns as in training
    feature_columns = ['having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service',
                       'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
                       'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
                       'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
                       'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
                       'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe',
                       'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
                       'Google_Index', 'Links_pointing_to_page', 'Statistical_report']
    
    for col in feature_columns:
        if col not in df:
            df[col] = 0  # Add missing features with default value
    
    return df[feature_columns]  # Return DataFrame with correct order

# 🔹 Step 4: Define API route for phishing detection
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()  # Get input JSON
        features = extract_features(data)  # Convert JSON to DataFrame
        prediction = model.predict(features)[0]  # Get prediction (0 = safe, 1 = phishing)
        return jsonify({"malicious": bool(prediction)})  # Return result as JSON
    except Exception as e:
        return jsonify({"error": str(e)}), 400  # Return error message if something goes wrong

# 🔹 Step 5: Run the Flask API
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
