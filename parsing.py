# ============================================================
# FINAL parsing.py (ULTIMATE COMPLETE VERSION)
# ============================================================

import re
import difflib
import math
import tldextract
from wordfreq import zipf_frequency
from textblob import TextBlob
import spacy

nlp = spacy.load("en_core_web_sm")

# ============================================================
# CONFIG
# ============================================================

TRUSTED_DOMAINS = [
    "company.com",
    "sharepoint.com",
    "google.com",
    "microsoft.com",
    "office.com"
]

LOW_TRUST_KEYWORDS = [
    "fileshare", "docs", "internal", "portal",
    "service", "cloud", "storage"
]

CREDENTIAL_WORDS = [
    "password", "login", "ssn", "credit card",
    "verify account", "confirm identity",
    "billing details", "account access",
    "account verification",
    "login credentials"
]

URGENT_WORDS = [
    "urgent", "immediately", "verify", "reset",
    "suspend", "action required", "asap"
]

SOCIAL_ENGINEERING_PHRASES = [
    "send me", "need you to", "asap", "right away",
    "urgent request", "quick favor", "in a meeting",
    "reply with", "confidential", "don’t tell anyone"
]

DATA_REQUEST_KEYWORDS = [
    "send me", "share", "provide", "forward",
    "vendor list", "employee list", "payroll",
    "w-2", "documents", "files"
]

# ============================================================
# CLEANING
# ============================================================

def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\.\S+", "", text)
    text = re.sub(r"\d+", "", text)
    text = re.sub(r"[^\w\s]", "", text)
    return re.sub(r"\s+", " ", text).strip()

# ============================================================
# DOMAIN HELPERS
# ============================================================

def extract_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}", ext.domain

def is_trusted_url(text):
    urls = re.findall(r"(https?://\S+|www\.\S+)", text)
    for url in urls:
        domain, _ = extract_domain(url)
        if domain in TRUSTED_DOMAINS:
            return 1
    return 0

# ============================================================
# DOMAIN ENTROPY
# ============================================================

def domain_entropy(domain):
    prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
    return -sum([p * math.log2(p) for p in prob])

# ============================================================
# DOMAIN DETECTION
# ============================================================

def advanced_domain_check(text):
    urls = re.findall(r"(https?://\S+|www\.\S+)", text)

    suspicious_keywords = [
        "secure", "login", "verify", "update",
        "account", "billing", "auth", "support"
    ]

    for url in urls:
        full_domain, base = extract_domain(url)

        # Brand impersonation
        for brand in ["google", "paypal", "amazon", "microsoft", "apple", "slack"]:
            if brand in base and base != brand:
                return 1

        if any(word in base for word in suspicious_keywords):
            return 1

        if any(word in base for word in LOW_TRUST_KEYWORDS):
            return 2

        if domain_entropy(base) > 3.5:
            return 1

    return 0

# ============================================================
# SOCIAL ENGINEERING
# ============================================================

def social_engineering_score(text):
    text = text.lower()
    return sum(1 for phrase in SOCIAL_ENGINEERING_PHRASES if phrase in text)

# ============================================================
# DATA EXFILTRATION DETECTION
# ============================================================

def data_exfiltration_score(text):
    text = text.lower()
    return sum(1 for word in DATA_REQUEST_KEYWORDS if word in text)

# ============================================================
# NLP FEATURES
# ============================================================

def detect_sensitive_entities(text):
    doc = nlp(text)
    return 1 if len([e for e in doc.ents if e.label_ in ["ORG", "PERSON"]]) >= 2 else 0

def unnatural_language_score(text):
    words = re.findall(r"\b[a-zA-Z]+\b", text.lower())
    return len([w for w in words if zipf_frequency(w, "en") < 2])

def sentiment_score(text):
    return TextBlob(text).sentiment.polarity

# ============================================================
# BASIC RULES
# ============================================================

def has_url(text): return 1 if re.search(r"http|www", text.lower()) else 0
def has_urgent_words(text): return 1 if any(w in text.lower() for w in URGENT_WORDS) else 0
def asks_for_credentials(text): return 1 if any(w in text.lower() for w in CREDENTIAL_WORDS) else 0

# ============================================================
# FEATURES
# ============================================================

def extract_rule_features(text):
    return {
        "has_url": has_url(text),
        "trusted_url": is_trusted_url(text),
        "has_urgent_words": has_urgent_words(text),
        "asks_for_credentials": asks_for_credentials(text),
        "advanced_domain_flag": advanced_domain_check(text),
        "social_engineering_score": social_engineering_score(text),
        "data_exfiltration_score": data_exfiltration_score(text),
        "contains_sensitive_entities": detect_sensitive_entities(text),
        "unnatural_language_score": unnatural_language_score(text),
        "sentiment_score": sentiment_score(text),
    }

# ============================================================
# SCORING
# ============================================================

def calculate_risk_score(confidence, prediction, f):
    base = confidence * 30

    if prediction == 1:
        base += 10

    if f["has_url"]:
        if f["trusted_url"]:
            base += 1
        elif f["advanced_domain_flag"] == 1:
            base += 22
        elif f["advanced_domain_flag"] == 2:
            base += 8
        else:
            base += 5

    if f["asks_for_credentials"]:
        base += 18

    if f["has_urgent_words"]:
        base += 10

    if f["social_engineering_score"] >= 2:
        base += 15

    if f["data_exfiltration_score"] >= 2:
        base += 10

    if f["contains_sensitive_entities"]:
        base += 6

    base += min(15, f["unnatural_language_score"] * 2)

    if f["sentiment_score"] < -0.5:
        base += 5

    return min(100, round(base))