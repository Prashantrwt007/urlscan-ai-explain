<div align="center">

# 🛡️ URLSCAN — Phishing URL Detector

**A full-stack web app that scores phishing risk in real time using a trained machine learning model — not a hardcoded rule engine.**

[![Node.js](https://img.shields.io/badge/Node.js-Express-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-scikit--learn-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen)]()

[Overview](#overview) · [Demo](#demo) · [Architecture](#architecture) · [Setup](#setup) · [Model](#model--methodology) · [Roadmap](#roadmap)

</div>

---

## Overview

URLSCAN takes a raw URL and returns a phishing risk score in under a second — no page is ever fetched, no DNS lookup happens, and no third-party API is called. Every signal is derived from the **structure of the URL string itself**: length, subdomain depth, embedded credentials, hyphenation, and 10 other lexical features, scored by a **Random Forest classifier** trained on 18,000 labeled URLs.

| | |
|---|---|
| **Frontend** | Vanilla HTML/CSS/JS — terminal-inspired dashboard |
| **Backend** | Node.js + Express API gateway |
| **ML Engine** | Python + scikit-learn (RandomForestClassifier) |
| **Dataset** | 18,000 URLs — 5,000 phishing (PhishTank-derived) + 13,000 legitimate (self-augmented from a top-1M domain ranking) |
| **Accuracy** | 89.1% on held-out test data |

---

## Demo

```
scan> http://paypal-secure-login-update@192.168.4.12/account/verify

  Classification: PHISHING          Risk Index: 96.4%
  ▲ URL contains an '@' symbol (can mask the real destination)
  ▲ Domain uses a raw IP address instead of a domain name
  ▲ Domain contains multiple hyphens
```

```
scan> https://en.wikipedia.org/wiki/Phishing

  Classification: SAFE               Risk Index: 7.1%
  ✓ No suspicious structural anomalies found
```

---

## Architecture

```
┌─────────────────────┐      POST /api/analyze       ┌──────────────────────┐
│   Frontend (HTML/JS)  │ ────────────────────────────▶ │  Express API Gateway  │
│   Terminal dashboard   │ ◀──────────────────────────── │     (server.js)        │
└─────────────────────┘        JSON verdict           └──────────┬───────────┘
                                                                    │ spawns child process
                                                                    ▼
                                                        ┌──────────────────────┐
                                                        │   Python inference     │
                                                        │  (model.py + joblib)   │
                                                        │  RandomForestClassifier │
                                                        └──────────────────────┘
```

**Request flow:** the browser posts a raw URL → Express hands it to a Python subprocess → `features.py` extracts 14 lexical features → the pre-trained model returns a probability → the API responds with a risk score, classification, and a human-readable list of triggered indicators.

---

## Setup

### Prerequisites
- [Node.js](https://nodejs.org/) 18+
- [Python](https://www.python.org/) 3.9+

### Install & run

```bash
git clone https://github.com/Prashantrwt007/url-phishing-detector.git
cd url-phishing-detector/backend

pip install -r requirements.txt
npm install

node server.js
```

Then open `frontend/index.html` in any browser. The dashboard talks to `http://127.0.0.1:5000` — leave the `node server.js` terminal running while you use it.

> Retraining is optional — `model.joblib` ships pre-trained. To retrain from scratch: `python train_model.py`.

---

## Model & Methodology

### The 14 features

All features are computed from the URL string alone — no network calls.

| Feature | Signal |
|---|---|
| `Have_IP` | Domain is a raw IP address |
| `Have_At` | `@` symbol present (credential-masking trick) |
| `URL_Length` | URL ≥ 54 characters |
| `URL_Depth` | Number of path segments |
| `Redirection` | Suspicious `//` later in the URL |
| `https_Domain` | Literal "https" text stuffed into the domain |
| `TinyURL` | Known link-shortening service |
| `Prefix_Suffix` | Hyphen in the domain |
| `Domain_Length` | Character length of the domain |
| `Digit_Count` | Digits in the domain |
| `Hyphen_Count` | Hyphens in the domain |
| `Dot_Count` | Dots in the domain |
| `Common_TLD` | Ends in `.com`/`.org`/`.net`/`.edu`/`.gov`/`.io`/`.co`/`.info` |
| `Subdomain_Count` | Number of subdomain levels |

### Dataset

The base dataset (phishing + legitimate URLs with these features pre-extracted) is derived from the UCI "Phishing Websites" lexical feature schema, via [`shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques`](https://github.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques).

**A bias I found and fixed:** the original "legitimate" class almost never included a bare root domain (`https://google.com`) — only 0.28% of legitimate rows had zero path depth, versus 13.5% of phishing rows. That sampling artifact caused the first trained model to flag `google.com` and `amazon.com` as ~94% phishing. I corrected it by generating **13,000 additional legitimate examples** from the [zer0h/top-1000000-domains](https://github.com/zer0h/top-1000000-domains) ranking, with randomized `www.`/subdomain prefixes and realistic path suffixes, so the legitimate class actually reflects how real traffic looks.

### Performance

Evaluated on a held-out 20% test split (3,600 URLs):

| Metric | Score |
|---|---|
| Accuracy | **89.1%** |
| Precision | 79.1% |
| Recall | 82.5% |
| F1 Score | 80.8% |

Top predictive features: `Domain_Length`, `URL_Length`, `URL_Depth`.

### Known limitations

- **No DNS/WHOIS/content signal** — a phishing site on a clean-looking, brand-new domain with no lexical red flags can slip through. Production systems layer in domain age, SSL issuance date, and page content analysis.
- **Precision/recall trade-off** — the model is tuned to flag genuinely suspicious patterns confidently (79% precision) while catching most real phishing (82.5% recall), rather than maximizing one at the other's expense.
- **Static training snapshot** — phishing patterns evolve; a production deployment would need periodic retraining on fresh data.

---

## Project structure

```
url-phishing-detector/
├── backend/
│   ├── features.py       # feature extraction (shared by training + inference)
│   ├── train_model.py     # trains and saves the RandomForest
│   ├── model.py            # loads the model, scores a single URL
│   ├── server.js            # Express API gateway
│   ├── dataset.csv           # training data (18,000 rows)
│   └── model.joblib           # pre-trained model
└── frontend/
    └── index.html               # dashboard UI
```

---

## Roadmap

- [ ] Deploy backend (Render/Railway) + frontend (Vercel) for a live public demo
- [ ] Add a persistence layer to log scanned URLs and results
- [ ] Optional domain-reputation lookup as a supplementary (non-blocking) signal
- [ ] Unit tests for `features.py`

---

<div align="center">

Built by [Prashant](https://github.com/Prashantrwt007)

</div>
