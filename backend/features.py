"""
features.py
Extracts 8 lexical/structural features from a raw URL string.
No network calls (no DNS, no WHOIS, no HTTP requests) — everything is
derived from the URL text alone, so this runs instantly and works offline.
These are the same feature definitions used to label the training dataset
(backend/dataset.csv), sourced from the well-known UCI "Phishing Websites"
lexical feature set.
"""

import re
from urllib.parse import urlparse

FEATURE_NAMES = [
    "Have_IP",
    "Have_At",
    "URL_Length",
    "URL_Depth",
    "Redirection",
    "https_Domain",
    "TinyURL",
    "Prefix_Suffix",
    "Domain_Length",
    "Digit_Count",
    "Hyphen_Count",
    "Dot_Count",
    "Common_TLD",
    "Subdomain_Count",
]

COMMON_TLDS = (".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".info")

SHORTENING_SERVICES = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|"
    r"is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|"
    r"su\.pr|twurl\.nl|snipurl\.com|short\.to|budurl\.com|ping\.fm|post\.ly|"
    r"just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|"
    r"kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|po\.st|"
    r"bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|"
    r"1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"
)

IP_PATTERN = re.compile(
    r"^(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])$"
)


def _get_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    return parsed.netloc or parsed.path


def have_ip(url: str) -> int:
    domain = _get_domain(url).split(":")[0]
    return 1 if IP_PATTERN.match(domain) else 0


def have_at(url: str) -> int:
    return 1 if "@" in url else 0


def url_length(url: str) -> int:
    return 1 if len(url) >= 54 else 0


def url_depth(url: str) -> int:
    parsed = urlparse(url if "://" in url else "http://" + url)
    segments = [s for s in parsed.path.split("/") if s]
    return len(segments)


def redirection(url: str) -> int:
    last_double_slash = url.rfind("//")
    return 1 if last_double_slash > 7 else 0


def https_in_domain(url: str) -> int:
    domain = _get_domain(url)
    return 1 if "https" in domain else 0


def tiny_url(url: str) -> int:
    return 1 if SHORTENING_SERVICES.search(url) else 0


def prefix_suffix(url: str) -> int:
    domain = _get_domain(url)
    return 1 if "-" in domain else 0


def domain_length(url: str) -> int:
    return len(_get_domain(url))


def digit_count(url: str) -> int:
    return sum(c.isdigit() for c in _get_domain(url))


def hyphen_count(url: str) -> int:
    return _get_domain(url).count("-")


def dot_count(url: str) -> int:
    return _get_domain(url).count(".")


def common_tld(url: str) -> int:
    domain = _get_domain(url).lower()
    return 1 if domain.endswith(COMMON_TLDS) else 0


def subdomain_count(url: str) -> int:
    return max(0, _get_domain(url).count(".") - 1)


def extract_features(url: str) -> dict:
    return {
        "Have_IP": have_ip(url),
        "Have_At": have_at(url),
        "URL_Length": url_length(url),
        "URL_Depth": url_depth(url),
        "Redirection": redirection(url),
        "https_Domain": https_in_domain(url),
        "TinyURL": tiny_url(url),
        "Prefix_Suffix": prefix_suffix(url),
        "Domain_Length": domain_length(url),
        "Digit_Count": digit_count(url),
        "Hyphen_Count": hyphen_count(url),
        "Dot_Count": dot_count(url),
        "Common_TLD": common_tld(url),
        "Subdomain_Count": subdomain_count(url),
    }


FEATURE_DESCRIPTIONS = {
    "Have_IP": "URL uses a raw IP address instead of a domain name",
    "Have_At": "URL contains an '@' symbol (can mask the real destination)",
    "URL_Length": "URL is unusually long (54+ characters)",
    "URL_Depth": "Unusually deep URL path (3+ segments)",
    "Redirection": "Suspicious '//' redirection later in the URL",
    "https_Domain": "The literal word 'https' appears inside the domain (spoofing trick)",
    "TinyURL": "URL was created with a known link-shortening service",
    "Prefix_Suffix": "Domain contains a hyphen (often used to mimic real brands)",
    "Domain_Length": "Domain name is unusually long",
    "Digit_Count": "Domain contains an unusual number of digits",
    "Hyphen_Count": "Domain contains multiple hyphens",
    "Dot_Count": "Domain contains an unusual number of dots",
    "Common_TLD": "Domain does NOT use a common top-level domain (.com/.org/.net/etc.)",
    "Subdomain_Count": "Unusually high number of subdomains",
}
