# ============================================================
# predict_local.py
#
# This script allows a user to manually test email text against
# the phishing detection system.
#
# PURPOSE:
#   1. Load the trained machine learning model
#   2. Load the saved TF-IDF vectorizer
#   3. Accept user email text input
#   4. Apply autocorrect and text cleaning
#   5. Extract phishing rule-based features
#   6. Run the machine learning classifier
#   7. Calculate a phishing risk score
#   8. Save the result to SQLite for logging/auditing
#
# OUTPUT:
#   - Prediction label
#   - Confidence score
#   - Risk score
#   - Rule-based phishing reasons
#   - Saved database record
#
# This is the main Sprint 2 demo script.
# ============================================================

import pickle

# ------------------------------------------------------------
# Import parsing functions
#
# These functions handle:
#   - text cleanup
#   - phishing feature extraction
#   - explanation generation
#   - risk scoring
# ------------------------------------------------------------

from parsing import (
    autocorrect_text,
    clean_text,
    extract_rule_features,
    get_flag_reasons,
    calculate_risk_score,
)

# ------------------------------------------------------------
# Import database functions
#
# These functions create the database table (if needed)
# and store scan results.
# ------------------------------------------------------------

from database import create_table, save_scan_result


# ------------------------------------------------------------
# STEP 1: Load machine learning model and vectorizer
#
# model.pkl was created in train_model.py
# vectorizer.pkl was created in feature_extraction.py
# ------------------------------------------------------------

print("Loading model and vectorizer...")

with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("data/vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

# ------------------------------------------------------------
# STEP 2: Ensure the SQLite database table exists
#
# If the table is not already created, this will create it.
# ------------------------------------------------------------

create_table()

print("Model, vectorizer, and database loaded successfully.")


# ------------------------------------------------------------
# STEP 3: Start user input loop
#
# The user can continuously test emails until they type "exit".
# ------------------------------------------------------------

while True:
    text = input("\nEnter an email to test (or type 'exit'): ")

    # Exit condition
    if text.lower() == "exit":
        break

    # --------------------------------------------------------
    # STEP 4: Generate preprocessing versions of the text
    #
    # autocorrected_text:
    #   fixes phishing-style typos and obfuscation
    #
    # cleaned_text:
    #   text version prepared for TF-IDF vectorization
    # --------------------------------------------------------

    autocorrected = autocorrect_text(text)
    cleaned = clean_text(text)

    # Convert cleaned text into TF-IDF feature vector
    features = vectorizer.transform([cleaned])

    # --------------------------------------------------------
    # STEP 5: Run machine learning prediction
    #
    # prediction:
    #   1 = phishing
    #   0 = legitimate
    #
    # confidence:
    #   highest probability from model output
    # --------------------------------------------------------

    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0]
    confidence = float(max(probability))

    # --------------------------------------------------------
    # STEP 6: Run rule-based phishing detection
    #
    # These are explicit phishing rules, separate from ML.
    # --------------------------------------------------------

    rule_features = extract_rule_features(text)

    # Get readable explanations such as:
    #   "Contains URL or domain"
    #   "Uses urgent language"
    reasons = get_flag_reasons(rule_features)

    # --------------------------------------------------------
    # STEP 7: Calculate risk score
    #
    # This combines:
    #   - ML confidence
    #   - phishing rule features
    #
    # Final score is from 0 to 100.
    # --------------------------------------------------------

    risk_score = calculate_risk_score(confidence, int(prediction), rule_features)

    # --------------------------------------------------------
    # STEP 8: Handle very short / meaningless input
    #
    # Example:
    #   "ts"
    #   ""
    #
    # These should not be treated as serious phishing detections.
    # --------------------------------------------------------

    cleaned_word_count = len(cleaned.split())

    # Count how many strong phishing rules are active
    suspicious_rule_count = sum([
        rule_features["has_url"],
        rule_features["has_urgent_words"],
        rule_features["asks_for_credentials"],
        rule_features["has_click_language"],
        1 if rule_features["typo_suspicion_score"] >= 2 else 0,
        rule_features["brand_impersonation"],
        rule_features["subdomain_phishing"],
        rule_features["homoglyph_attack"],
        rule_features["suspicious_tld"],
    ])

    # Decision logic
    if cleaned_word_count < 3 and suspicious_rule_count == 0:
        label = "Insufficient content"
        risk_score = min(risk_score, 20)

    elif prediction == 1 and suspicious_rule_count == 0 and cleaned_word_count < 5:
        label = "Insufficient content"
        risk_score = min(risk_score, 25)

    elif prediction == 0 and suspicious_rule_count >= 3:
        # Rule-based escalation:
        # even if model says legitimate, enough phishing rules
        # can override it
        label = "Phishing (rule-escalated)"

    else:
        label = "Phishing" if prediction == 1 else "Legitimate"

    # --------------------------------------------------------
    # STEP 9: Convert reasons into a single readable string
    # --------------------------------------------------------

    flag_reason_text = "; ".join(reasons) if reasons else "No major phishing flags detected"

    # --------------------------------------------------------
    # STEP 10: Build result dictionary
    #
    # This is what gets saved to the database.
    # --------------------------------------------------------

    result = {
        "original_text": text,
        "autocorrected_text": autocorrected,
        "cleaned_text": cleaned,
        "prediction_label": label,
        "model_confidence": round(confidence, 4),
        "risk_score": risk_score,
        "has_url": rule_features["has_url"],
        "has_urgent_words": rule_features["has_urgent_words"],
        "asks_for_credentials": rule_features["asks_for_credentials"],
        "suspicious_symbol_count": rule_features["suspicious_symbol_count"],
        "uppercase_ratio": round(rule_features["uppercase_ratio"], 4),
        "flag_reasons": flag_reason_text,
    }

    # --------------------------------------------------------
    # STEP 11: Save scan result to SQLite database
    # --------------------------------------------------------

    save_scan_result(result)

    # --------------------------------------------------------
    # STEP 12: Print output to user
    #
    # This is the terminal output shown in the demo.
    # --------------------------------------------------------

    print("\nAutocorrected Text:")
    print(autocorrected[:300])

    print("\nPrediction:", label)
    print("Confidence:", round(confidence, 4))
    print("Risk Score:", risk_score, "/ 100")
    print("Rule Features:", rule_features)
    print("Flag Reasons:", flag_reason_text)
    print("Saved to database.")