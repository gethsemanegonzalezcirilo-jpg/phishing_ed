# ============================================================
# parsing.py
#
# This file contains all rule-based phishing detection logic
# for the phishing email detector project.
#
# PURPOSE:
# This module looks at raw email text and checks for common
# phishing indicators that attackers often use.
#
# The machine learning model handles pattern recognition,
# while this file handles explicit phishing rules.
#
# Together, this creates a hybrid phishing detection system.
#
# This file detects:
#   - URLs / domains
#   - urgent language
#   - requests for credentials
#   - click-through language
#   - suspicious misspellings / obfuscation
#   - brand impersonation
#   - multi-level subdomain phishing
#   - homoglyph attacks (look-alike characters)
#   - suspicious top-level domains
#
# The final output of this file is:
#   1. rule-based phishing features
#   2. human-readable flag reasons
#   3. a phishing risk score
# ============================================================

import re
import difflib


# ============================================================
# COMMON TYPO CORRECTIONS
#
# These are common phishing-style misspellings or shorthand
# terms attackers may use to bypass simple filters.
#
# Example:
#   "verfy"  -> "verify"
#   "accnt"  -> "account"
#   "clik"   -> "click"
# ============================================================

COMMON_TYPOS = {
    "verfy": "verify",
    "acct": "account",
    "accnt": "account",
    "passwrod": "password",
    "pasword": "password",
    "logn": "login",
    "singin": "signin",
    "updte": "update",
    "suspened": "suspended",
    "immediatly": "immediately",
    "secuirty": "security",
    "confim": "confirm",
    "tht": "that",
    "yu": "you",
    "ur": "your",
    "clik": "click",
}


# ============================================================
# URGENT PHISHING LANGUAGE
#
# Phishing emails often pressure the victim into acting fast.
# These words or phrases signal urgency.
# ============================================================

URGENT_WORDS = [
    "urgent",
    "immediately",
    "verify",
    "reset",
    "suspend",
    "action required",
    "final warning",
    "account locked",
    "confirm now",
    "failure to act",
    "limited",
    "security alert",
]


# ============================================================
# CREDENTIAL REQUEST LANGUAGE
#
# These are common phishing terms used when an attacker is
# trying to get a user’s password, account data, or payment
# information.
# ============================================================

CREDENTIAL_WORDS = [
    "password",
    "login",
    "sign in",
    "signin",
    "verify account",
    "confirm account",
    "bank account",
    "ssn",
    "credit card",
    "credentials",
    "account information",
    "payment details",
    "billing information",
]


# ============================================================
# CLICK-THROUGH PHRASES
#
# Many phishing emails instruct the user to click something.
# These phrases are used to detect that behavior.
# ============================================================

CLICK_PHRASES = [
    "click this link",
    "click this url",
    "click below",
    "follow this link",
    "click here",
    "use the secure link below",
    "restore access",
]


# ============================================================
# SUSPICIOUS TYPO TOKENS
#
# If multiple suspicious misspellings are present, the email
# may be intentionally obfuscated.
# ============================================================

SUSPICIOUS_TYPOS = {
    "tht",
    "yu",
    "verfy",
    "updte",
    "immediatly",
    "clik",
    "logn",
    "passwrod",
    "pasword",
    "acct",
    "accnt",
    "suspened",
}


# ============================================================
# KNOWN BRANDS
#
# These brands are commonly impersonated in phishing campaigns.
# We compare detected domains against these names.
# ============================================================

KNOWN_BRANDS = [
    "google",
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "facebook",
    "netflix",
    "bankofamerica",
]


# ============================================================
# SUSPICIOUS TOP-LEVEL DOMAINS (TLDs)
#
# Many phishing domains use unusual or cheap TLDs.
# Examples:
#   .xyz
#   .top
#   .click
# ============================================================

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".ru",
    ".cn",
    ".work",
    ".support",
    ".security",
    ".loan",
]


# ============================================================
# HOMOGLYPH ATTACK PATTERNS
#
# Attackers replace letters with visually similar characters.
#
# Example:
#   paypal  -> paypaI   (capital I)
#   google  -> g00gle
#   amazon  -> amaz0n
# ============================================================

HOMOGLYPH_PATTERNS = [
    "paypaI",
    "g00gle",
    "amaz0n",
    "micr0soft",
    "faceb00k",
    "netfIix",
]


# ============================================================
# normalize_obfuscation(text)
#
# PURPOSE:
# Converts common obfuscated characters back into letters.
#
# Example:
#   g00gle -> google
#   amaz0n -> amazon
#   p@ypal -> paypal
#
# This makes later detection rules more accurate.
# ============================================================

def normalize_obfuscation(text: str) -> str:
    text = str(text)

    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "@": "a",
        "$": "s",
    }

    for wrong, right in replacements.items():
        text = text.replace(wrong, right)

    return text


# ============================================================
# autocorrect_text(text)
#
# PURPOSE:
# Applies lightweight typo correction and obfuscation cleanup.
#
# This is not full English spellcheck. It is a targeted cleanup
# designed for phishing-style misspellings.
# ============================================================

def autocorrect_text(text: str) -> str:
    text = normalize_obfuscation(text)

    for wrong, right in COMMON_TYPOS.items():
        text = re.sub(rf"\b{re.escape(wrong)}\b", right, text, flags=re.IGNORECASE)

    return text


# ============================================================
# clean_text(text)
#
# PURPOSE:
# Prepares text for the machine learning model.
#
# Steps:
#   1. autocorrect suspicious misspellings
#   2. lowercase text
#   3. remove URLs
#   4. remove digits
#   5. remove punctuation
#   6. normalize whitespace
#
# This cleaned text is what gets converted into TF-IDF features.
# ============================================================

def clean_text(text: str) -> str:
    text = autocorrect_text(text)
    text = text.lower()

    # Remove explicit URLs like http://example.com or www.example.com
    text = re.sub(r"http\S+|www\.\S+", "", text)

    # Remove digits
    text = re.sub(r"\d+", "", text)

    # Remove punctuation and special characters
    text = re.sub(r"[^\w\s]", "", text)

    # Remove repeated whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text


# ============================================================
# has_url(text)
#
# PURPOSE:
# Detect whether the email contains a URL or domain.
#
# Returns:
#   1 if a URL/domain is found
#   0 otherwise
#
# This catches:
#   - http://example.com
#   - www.example.com
#   - fake-login.top
# ============================================================

def has_url(text: str) -> int:
    text = normalize_obfuscation(str(text).lower())

    # Detect full URLs
    if re.search(r"http[s]?://|www\.", text):
        return 1

    # Detect plain domains
    if re.search(r"\b[a-zA-Z0-9-]+\.(com|net|org|xyz|top|click|ru|cn|work|support|security|loan)\b", text):
        return 1

    return 0


# ============================================================
# detect_subdomain_phishing(text)
#
# PURPOSE:
# Detect suspicious multi-level domains like:
#   amazon.com.secure-payments.co
#
# This is a common phishing trick where the real-looking brand
# is placed at the front of a fake domain.
#
# Returns:
#   1 if a suspicious multi-level domain is found
#   0 otherwise
# ============================================================

def detect_subdomain_phishing(text: str) -> int:
    text = normalize_obfuscation(str(text).lower())

    matches = re.findall(r"[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}", text)

    for domain in matches:
        parts = domain.split(".")
        if len(parts) >= 3:
            return 1

    return 0


# ============================================================
# has_urgent_words(text)
#
# PURPOSE:
# Detect whether the email uses pressure / urgency language.
#
# Returns:
#   1 if urgent wording is present
#   0 otherwise
# ============================================================

def has_urgent_words(text: str) -> int:
    text = str(text).lower()

    for word in URGENT_WORDS:
        if word in text:
            return 1

    return 0


# ============================================================
# asks_for_credentials(text)
#
# PURPOSE:
# Detect whether the email asks for passwords, logins,
# payment info, or account credentials.
#
# Returns:
#   1 if credential-related language is present
#   0 otherwise
# ============================================================

def asks_for_credentials(text: str) -> int:
    text = str(text).lower()

    for word in CREDENTIAL_WORDS:
        if word in text:
            return 1

    return 0


# ============================================================
# has_click_language(text)
#
# PURPOSE:
# Detect whether the email is instructing the user to click.
#
# Returns:
#   1 if click-through language is found
#   0 otherwise
# ============================================================

def has_click_language(text: str) -> int:
    text = normalize_obfuscation(str(text).lower())

    # Clean up common obfuscated click-language patterns
    text = text.replace("cllck", "click")
    text = text.replace("thls", "this")
    text = text.replace("llnk", "link")

    for phrase in CLICK_PHRASES:
        if phrase in text:
            return 1

    return 0


# ============================================================
# suspicious_symbol_count(text)
#
# PURPOSE:
# Count suspicious punctuation often used in scams.
#
# Examples:
#   !!!
#   $$$
#   %%%
# ============================================================

def suspicious_symbol_count(text: str) -> int:
    text = str(text)
    return text.count("!") + text.count("$") + text.count("%")


# ============================================================
# uppercase_ratio(text)
#
# PURPOSE:
# Calculate how much of the text is uppercase.
#
# Phishing emails often use ALL CAPS to create pressure.
#
# Returns:
#   ratio between 0 and 1
# ============================================================

def uppercase_ratio(text: str) -> float:
    text = str(text)

    letters = sum(1 for c in text if c.isalpha())
    uppers = sum(1 for c in text if c.isupper())

    return uppers / letters if letters > 0 else 0


# ============================================================
# typo_suspicion_score(text)
#
# PURPOSE:
# Count how many suspicious typo words appear in the email.
#
# A higher count suggests the text may be intentionally
# obfuscated or low-quality phishing.
# ============================================================

def typo_suspicion_score(text: str) -> int:
    words = re.findall(r"\b[a-zA-Z]+\b", str(text).lower())
    count = 0

    for word in words:
        if word in SUSPICIOUS_TYPOS:
            count += 1

    return count


# ============================================================
# looks_like_brand_domain(text)
#
# PURPOSE:
# Detect whether a domain looks similar to a known brand.
#
# Example:
#   goog1e-login.com
#   amaz0n-security.com
#
# Returns:
#   1 if a likely brand impersonation is found
#   0 otherwise
# ============================================================

def looks_like_brand_domain(text: str) -> int:
    text = normalize_obfuscation(str(text).lower())

    domains = re.findall(
        r"[a-zA-Z0-9\-]+\.(?:com|net|org|co|io|xyz|top|click|ru|cn|work|support|security|loan)",
        text
    )

    for domain in domains:
        name = domain.split(".")[0]

        for brand in KNOWN_BRANDS:
            similarity = difflib.SequenceMatcher(None, name, brand).ratio()

            # Similar but not exact = suspicious
            if similarity > 0.75 and name != brand:
                return 1

    return 0


# ============================================================
# detect_homoglyph_attack(text)
#
# PURPOSE:
# Detect look-alike character substitutions.
#
# Example:
#   paypaI.com
#   g00gle.com
#
# Returns:
#   1 if known homoglyph pattern is found
#   0 otherwise
# ============================================================

def detect_homoglyph_attack(text: str) -> int:
    for pattern in HOMOGLYPH_PATTERNS:
        if pattern.lower() in str(text).lower():
            return 1

    return 0


# ============================================================
# detect_suspicious_tld(text)
#
# PURPOSE:
# Detect suspicious or phishing-prone domain extensions.
#
# Example:
#   .xyz
#   .top
#   .click
#
# Returns:
#   1 if suspicious TLD is found
#   0 otherwise
# ============================================================

def detect_suspicious_tld(text: str) -> int:
    text = str(text).lower()

    for tld in SUSPICIOUS_TLDS:
        if tld in text:
            return 1

    return 0


# ============================================================
# extract_rule_features(text)
#
# PURPOSE:
# Run all phishing detection rules and return the results in a
# single dictionary.
#
# This dictionary is later used for:
#   - flag explanations
#   - risk scoring
#   - database storage
# ============================================================

def extract_rule_features(text: str) -> dict:
    return {
        "has_url": has_url(text),
        "has_urgent_words": has_urgent_words(text),
        "asks_for_credentials": asks_for_credentials(text),
        "has_click_language": has_click_language(text),
        "suspicious_symbol_count": suspicious_symbol_count(text),
        "uppercase_ratio": uppercase_ratio(text),
        "typo_suspicion_score": typo_suspicion_score(text),
        "brand_impersonation": looks_like_brand_domain(text),
        "subdomain_phishing": detect_subdomain_phishing(text),
        "homoglyph_attack": detect_homoglyph_attack(text),
        "suspicious_tld": detect_suspicious_tld(text),
    }


# ============================================================
# get_flag_reasons(features)
#
# PURPOSE:
# Convert rule features into human-readable explanations.
#
# These explanations are shown to the user and also stored in
# the database.
# ============================================================

def get_flag_reasons(features: dict) -> list[str]:
    reasons = []

    if features["has_url"]:
        reasons.append("Contains URL or domain")

    if features["has_urgent_words"]:
        reasons.append("Uses urgent language")

    if features["asks_for_credentials"]:
        reasons.append("Requests credentials or account verification")

    if features["has_click_language"]:
        reasons.append("Uses click-through language")

    if features["typo_suspicion_score"] >= 2:
        reasons.append("Contains suspicious misspellings or obfuscation")

    if features["brand_impersonation"]:
        reasons.append("Domain impersonates a known brand")

    if features["subdomain_phishing"]:
        reasons.append("Suspicious multi-level domain (possible phishing redirect)")

    if features["homoglyph_attack"]:
        reasons.append("Look-alike character substitution detected")

    if features["suspicious_tld"]:
        reasons.append("Suspicious domain extension detected")

    return reasons


# ============================================================
# calculate_risk_score(model_confidence, prediction_label, features)
#
# PURPOSE:
# Combine the machine learning model’s confidence with the
# phishing rule features to create a final 0-100 risk score.
#
# Higher score = more suspicious
#
# The final score is capped at 100.
# ============================================================

def calculate_risk_score(model_confidence: float, prediction_label: int, features: dict) -> int:
    # If the model predicts phishing, start with a higher base
    if prediction_label == 1:
        base_score = model_confidence * 50
    else:
        base_score = model_confidence * 20

    # Add score if model itself says phishing
    if prediction_label == 1:
        base_score += 15

    # Add score for specific phishing signals
    if features["has_url"]:
        base_score += 12

    if features["has_urgent_words"]:
        base_score += 8

    if features["asks_for_credentials"]:
        base_score += 12

    if features["has_click_language"]:
        base_score += 8

    if features["typo_suspicion_score"] >= 2:
        base_score += 10

    if features["brand_impersonation"]:
        base_score += 15

    if features["subdomain_phishing"]:
        base_score += 15

    if features["homoglyph_attack"]:
        base_score += 20

    if features["suspicious_tld"]:
        base_score += 15

    # Limit score to 100 max
    return min(100, round(base_score))