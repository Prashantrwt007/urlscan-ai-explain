"""
train_model.py
Trains a RandomForestClassifier on dataset.csv (10,000 URLs, 5,000
phishing / 5,000 legitimate, 8 lexical/structural features) and saves
the trained model to model.joblib.

Dataset provenance: derived from the widely-used UCI "Phishing Websites"
lexical feature set (phishing URLs from PhishTank, legitimate URLs from
Alexa/UNB benign URL lists). Only the features that can be computed from
the URL string alone (no DNS/WHOIS/live page fetch) were kept, so the
trained model matches features.py used at inference time.

Run:
    python train_model.py
Produces:
    model.joblib   -- trained model
    metrics.json   -- accuracy/precision/recall for the README / interview talk track
"""

import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from features import FEATURE_NAMES

DATA_PATH = "dataset.csv"
MODEL_PATH = "model.joblib"
METRICS_PATH = "metrics.json"


def main():
    df = pd.read_csv(DATA_PATH)

    X = df[FEATURE_NAMES]
    y = df["Label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=3,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "feature_importances": {
            name: round(float(imp), 4)
            for name, imp in zip(FEATURE_NAMES, model.feature_importances_)
        },
    }

    joblib.dump(model, MODEL_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print("Model trained and saved to", MODEL_PATH)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
