# ============================================================
# LOCAL PREDICTION (FINAL - TUNED + CONSISTENT)
# ============================================================

import pickle
from parsing import clean_text, extract_rule_features, calculate_risk_score
from database import create_table, save_scan_result

print("Loading model...")

with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("data/vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

create_table()

print("System ready.")

while True:
    text = input("\nEnter an email (or type 'exit'): ")

    if text.lower() == "exit":
        break

    # ==============================
    # CLEAN + VECTORIZE
    # ==============================
    cleaned = clean_text(text)
    X = vectorizer.transform([cleaned])

    prediction = model.predict(X)[0]
    probs = model.predict_proba(X)[0]
    confidence = float(max(probs))

    f = extract_rule_features(text)

    # ==============================
    # BASE RISK
    # ==============================
    risk = calculate_risk_score(confidence, prediction, f)

    # ==============================
    # 🔥 FINAL TUNED RISK BOOSTS
    # ==============================

    # HIGH RISK
    if f["asks_for_credentials"]:
        risk += 30

    # SPOOFED DOMAIN (important)
    if f["advanced_domain_flag"] == 1:
        risk += 20

    # WEAK DOMAIN (reduced)
    if f["advanced_domain_flag"] == 2:
        risk += 3

    # SOCIAL ENGINEERING
    if f["social_engineering_score"] >= 2:
        risk += 8

    # Moderate data request (FINAL FIX)
    if f["data_exfiltration_score"] == 1:
        risk += 15   

    # Strong data exfiltration
    if f["data_exfiltration_score"] >= 2:
        risk += 20   

    # URGENCY
    if f["has_urgent_words"]:
        risk += 5

    # GENERIC UNTRUSTED URL
    if f["has_url"] and not f["trusted_url"]:
        risk += 5

    # Clamp risk
    risk = max(0, min(risk, 100))

    # ==============================
    # 🔥 LEGIT BUSINESS CONTEXT REDUCTION (FINAL FIX)
    # ==============================

    # If no strong phishing indicators, reduce risk slightly
    if (
        not f["has_url"]
        and not f["asks_for_credentials"]
        and f["data_exfiltration_score"] <= 1
        and f["social_engineering_score"] <= 1
    ):
        risk -= 5

    # ==============================
    # FINAL LABEL
    # ==============================
    if risk >= 70:
        label = "Phishing"
    elif risk >= 40:
        label = "Suspicious"
    else:
        label = "Legitimate"

    # ==============================
    # REASONS
    # ==============================
    reasons = []

    if f["asks_for_credentials"]:
        reasons.append("This email requests sensitive information such as login credentials.")

    if f["advanced_domain_flag"] == 1:
        reasons.append("The link appears to impersonate a trusted service but uses a suspicious domain.")

    if f["advanced_domain_flag"] == 2:
        reasons.append("The link uses an uncommon or low-trust domain.")

    if f["social_engineering_score"] >= 2:
        reasons.append("The message uses social engineering techniques to manipulate the recipient.")

    if f["data_exfiltration_score"] >= 2:
        reasons.append("The email requests potentially sensitive data.")

    if f["has_urgent_words"]:
        reasons.append("The message uses urgency to pressure immediate action.")

    if f["has_url"] and not f["trusted_url"]:
        reasons.append("The email contains a link from an untrusted domain.")

    # 🔥 CLEAN LEGIT MESSAGE FIX
    if not reasons:
        if label == "Legitimate":
            reasons.append("No phishing indicators were detected in this email.")
        else:
            reasons.append("This email was flagged based on learned patterns from the detection model.")

    reason_text = "; ".join(reasons)

    # ==============================
    # OUTPUT
    # ==============================
    print("\n--- RESULT ---")
    print("Prediction:", label)
    print("Confidence:", round(confidence, 4))
    print("Risk Score:", risk)
    print("Reasons:", reason_text)

    # ==============================
    # SAVE
    # ==============================
    save_scan_result({
        "original_text": text,
        "autocorrected_text": cleaned,
        "cleaned_text": cleaned,
        "prediction_label": label,
        "model_confidence": confidence,
        "risk_score": risk,
        "has_url": f["has_url"],
        "has_urgent_words": f["has_urgent_words"],
        "asks_for_credentials": f["asks_for_credentials"],
        "suspicious_symbol_count": 0,
        "uppercase_ratio": 0,
        "flag_reasons": reason_text,
    })