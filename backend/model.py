"""
model.py
Loads the trained RandomForest (model.joblib) and scores a single URL
passed in as a command-line argument. Called by server.js via a child
process for each /api/analyze request.

Usage:
    python model.py "https://example.com/suspicious-login"
Outputs (stdout):
    JSON: { url, risk_score, status, indicators, features }
"""

import sys
import json
import joblib

from features import extract_features, FEATURE_NAMES, FEATURE_DESCRIPTIONS

MODEL_PATH = "model.joblib"


def classify(url: str) -> dict:
    model = joblib.load(MODEL_PATH)

    feats = extract_features(url)
    ordered = [[feats[name] for name in FEATURE_NAMES]]

    # probability of class 1 (phishing)
    proba = model.predict_proba(ordered)[0][1]
    risk_score = round(proba * 100, 2)

    if risk_score >= 60:
        status = "Phishing"
    elif risk_score >= 30:
        status = "Suspicious"
    else:
        status = "Safe"

    # Each feature needs its own trigger rule: some are binary red flags,
    # some are counts (only worth flagging past a threshold), and Common_TLD
    # is inverted (1 = good, so the flag fires when it's 0).
    triggers = {
        "Have_IP": feats["Have_IP"] == 1,
        "Have_At": feats["Have_At"] == 1,
        "URL_Length": feats["URL_Length"] == 1,
        "URL_Depth": feats["URL_Depth"] >= 3,
        "Redirection": feats["Redirection"] == 1,
        "https_Domain": feats["https_Domain"] == 1,
        "TinyURL": feats["TinyURL"] == 1,
        "Prefix_Suffix": feats["Prefix_Suffix"] == 1,
        "Domain_Length": feats["Domain_Length"] >= 25,
        "Digit_Count": feats["Digit_Count"] >= 4,
        "Hyphen_Count": feats["Hyphen_Count"] >= 2,
        "Dot_Count": feats["Dot_Count"] >= 3,
        "Common_TLD": feats["Common_TLD"] == 0,
        "Subdomain_Count": feats["Subdomain_Count"] >= 2,
    }
    triggered = [FEATURE_DESCRIPTIONS[name] for name, fired in triggers.items() if fired]

    return {
        "url": url,
        "risk_score": risk_score,
        "status": status,
        "indicators": triggered if triggered else ["No suspicious structural anomalies found"],
        "features": feats,
    }


if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = classify(sys.argv[1])
        print(json.dumps(result))
    else:
        print(json.dumps({"error": "No URL argument supplied"}))
