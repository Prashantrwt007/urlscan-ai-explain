# URLSCAN — Full-Stack Phishing URL Detector

A full-stack app that scores a URL's phishing risk in real time using a
**real, trained** scikit-learn model — not a hand-coded if/else heuristic.

```
[ React-free HTML/JS frontend ]
              │  POST /api/analyze { url }
              ▼
[ Node.js / Express API gateway ]
              │  spawns child process
              ▼
[ Python: RandomForestClassifier ]  →  { risk_score, status, indicators }
```

## Why this dataset / these features

The model is trained only on **lexical/structural** features — things
computable from the URL string itself, with zero network calls (no DNS,
no WHOIS, no page fetch). That's a deliberate trade-off: it makes the
tool instant and works offline, at the cost of missing signals like
domain age or web traffic rank that a production system would use.

**Training data (`backend/dataset.csv`, 18,000 rows):**
- 5,000 phishing URLs + a legitimate-URL subset, originally sourced from
  a PhishTank/UNB-derived feature set (`shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques`
  on GitHub, itself built on the UCI "Phishing Websites" feature schema).
- **13,000 augmented legitimate examples** I generated myself from the
  [zer0h/top-1000000-domains](https://github.com/zer0h/top-1000000-domains)
  ranked domain list, with randomized `www.`/subdomain prefixes and
  realistic path suffixes.

  *Why the augmentation was necessary:* the original "legitimate" URLs
  in that dataset almost never included a bare root domain
  (`https://google.com`) or a common subdomain pattern — only 0.28% of
  legit rows had zero path depth, vs. 13.5% of phishing rows. That's a
  sampling artifact of how the original dataset was scraped, and it
  meant the raw model classified `google.com` and `amazon.com` as
  phishing with >90% confidence. I fixed this by generating thousands
  of realistic legitimate examples from a real top-sites ranking rather
  than just tuning thresholds until the demo looked right — worth
  knowing this history if you're asked "how did you validate the
  model," because it's a genuinely good story about catching a biased
  training set.

## The 14 features

| Feature | What it captures |
|---|---|
| `Have_IP` | Domain is a raw IP address |
| `Have_At` | `@` symbol in the URL (credential-masking trick) |
| `URL_Length` | URL ≥ 54 characters |
| `URL_Depth` | Number of path segments |
| `Redirection` | Suspicious `//` later in the URL |
| `https_Domain` | Literal "https" text stuffed into the domain |
| `TinyURL` | Known link-shortener service |
| `Prefix_Suffix` | Hyphen in the domain |
| `Domain_Length` | Character length of the domain |
| `Digit_Count` | Digits in the domain |
| `Hyphen_Count` | Hyphens in the domain |
| `Dot_Count` | Dots in the domain |
| `Common_TLD` | Ends in .com/.org/.net/.edu/.gov/.io/.co/.info |
| `Subdomain_Count` | Number of subdomain levels |

## Model performance (`backend/metrics.json`, regenerated on training)

- **Accuracy:** ~93.8% (held-out 20% test split)
- **Precision:** ~94% — when it says "Phishing," it's right most of the time
- **Recall:** ~85.5% — it misses some phishing URLs that look structurally clean
- Biggest feature importances: `Domain_Length`, `URL_Length`, `URL_Depth`

## Known limitations (say these out loud in an interview — it's a strength, not a weakness)

- **No content/DNS/WHOIS signal.** A phishing site hosted on a short,
  clean-looking, brand-new domain with no red-flag characters will slip
  through. Production systems add domain age, SSL cert issuance date,
  and page content analysis.
- **Ambiguous middle ground.** A bare well-known domain
  (`amazon.com`) or an unfamiliar-but-legitimate subdomain+path combo
  can land in "Suspicious" rather than a confident "Safe," because
  lexical features alone can't fully distinguish "unfamiliar" from
  "malicious." This is a real, documented limitation of URL-lexical-only
  phishing detection in the literature, not a bug — the model is tuned
  to lean cautious rather than confidently wrong.
- **Static training snapshot.** Phishing patterns evolve; a deployed
  version would need periodic retraining on fresh PhishTank data.

## Setup

```bash
# 1. Backend
cd backend
pip install -r requirements.txt
npm install
python train_model.py     # optional: retrains model.joblib from dataset.csv
node server.js             # starts API on http://localhost:5000

# 2. Frontend
# just open frontend/index.html in a browser (it calls localhost:5000)
```

## Interview script

**The problem:** "Static blacklist-based phishing filters miss new URLs.
I built a system that scores a URL structurally, in real time, using a
model trained on real phishing and legitimate URL data."

**The architecture:** "The frontend posts the raw URL to an Express
API. Express spawns a Python child process that extracts 14 lexical
features and runs them through a pre-trained RandomForest, and returns
a JSON verdict the frontend renders as a risk meter."

**A challenge I hit:** "When I first trained the model, it flagged
`google.com` as 94% phishing. I dug into the training data and found
the 'legitimate' class almost never included bare root domains — a
sampling bias in the source dataset. I fixed it by augmenting the
legitimate class with thousands of real top-ranked domains in
realistic URL shapes, which took accuracy from a misleading number down
to an honest, validated 93.8%."

**Trade-offs:** "I deliberately excluded content- and network-based
features (DNS, WHOIS, page fetch) so the tool works instantly and
offline — the cost is it can't catch phishing sites that just don't
look suspicious lexically."
