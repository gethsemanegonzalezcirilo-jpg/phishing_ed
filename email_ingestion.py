# ============================================================
# email_ingestion.py (UPDATED: Inbox + Spam Support)
# ============================================================

import time
import pickle

from imapclient import IMAPClient
import pyzmail

from parsing import (
    autocorrect_text,
    clean_text,
    extract_rule_features,
    get_flag_reasons,
    calculate_risk_score,
)
from database import create_table, save_scan_result


# ============================================================
# EMAIL CONFIGURATION
# ============================================================

EMAIL = "phishing.email.detector@gmail.com"
PASSWORD = "kibhkzlufqpoehya"
IMAP_HOST = "imap.gmail.com"
CHECK_INTERVAL = 10


# ============================================================
# TRUSTED DOMAINS
# ============================================================

TRUSTED_DOMAINS = [
    "google.com",
    "accounts.google.com",
    "notifications.google.com",
    "paypal.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "netflix.com",
]


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def extract_domain(email_address: str) -> str:
    if "@" in email_address:
        return email_address.split("@")[-1].lower().strip()
    return ""


def is_trusted_sender(sender_email: str) -> int:
    domain = extract_domain(sender_email)
    return 1 if domain in TRUSTED_DOMAINS else 0


# ============================================================
# LOAD MODEL + VECTORIZER
# ============================================================

print("Loading phishing model and vectorizer...")

with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("data/vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

create_table()

print("Model, vectorizer, and database loaded successfully.")


# ============================================================
# SESSION MEMORY
# ============================================================

processed_uids = set()


# ============================================================
# EMAIL PROCESSING FUNCTION
# ============================================================

def process_email(uid, message_data, folder_name, label_hint):
    msg = pyzmail.PyzMessage.factory(message_data[b"RFC822"])

    # Extract sender
    sender_email = "unknown"
    from_addresses = msg.get_addresses("from")
    if from_addresses:
        _, sender_email = from_addresses[0]

    sender_email = sender_email or "unknown"

    # Subject
    subject = msg.get_subject() or "(No Subject)"

    # Body
    if msg.text_part:
        body = msg.text_part.get_payload().decode(
            msg.text_part.charset or "utf-8",
            errors="ignore"
        )
    elif msg.html_part:
        body = msg.html_part.get_payload().decode(
            msg.html_part.charset or "utf-8",
            errors="ignore"
        )
    else:
        body = ""

    full_text = f"{subject} {body}".strip()

    if not full_text:
        print(f"\nSkipping UID {uid}: empty email content.")
        return

    # Preprocess
    autocorrected = autocorrect_text(full_text)
    cleaned = clean_text(full_text)

    # ML prediction
    features = vectorizer.transform([cleaned])
    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0]
    confidence = float(max(probability))

    # Rule features
    rule_features = extract_rule_features(autocorrected)
    reasons = get_flag_reasons(rule_features)

    # Risk score
    risk_score = calculate_risk_score(confidence, int(prediction), rule_features)

    # Trusted sender
    trusted_sender = is_trusted_sender(sender_email)
    if trusted_sender:
        risk_score = max(0, risk_score - 25)

    # Final logic
    cleaned_word_count = len(cleaned.split())

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

    if cleaned_word_count < 3 and suspicious_rule_count == 0:
        label = "Insufficient content"
        risk_score = min(risk_score, 20)

    elif trusted_sender and prediction == 1:
        if suspicious_rule_count >= 3:
            label = "Review Needed"
        else:
            label = "Likely Legitimate"

    elif prediction == 0 and suspicious_rule_count >= 3:
        label = "Phishing (rule-escalated)"

    else:
        label = "Phishing" if prediction == 1 else "Legitimate"

    flag_reason_text = "; ".join(reasons) if reasons else "No major phishing flags detected"

    if trusted_sender:
        if flag_reason_text == "No major phishing flags detected":
            flag_reason_text = "Trusted sender domain"
        else:
            flag_reason_text += "; Trusted sender domain"

    # Save
    result = {
        "original_text": full_text,
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
        "source_folder": folder_name,
        "label_hint": label_hint,
    }

    save_scan_result(result)

    # Print
    print("\n--- EMAIL SCANNED ---")
    print("UID:", uid)
    print("Folder:", folder_name)
    print("From:", sender_email)
    print("Subject:", subject)
    print("Prediction:", label)
    print("Confidence:", round(confidence, 4))
    print("Risk Score:", risk_score, "/ 100")
    print("Saved to database.")


# ============================================================
# SCAN FOLDER FUNCTION
# ============================================================

def scan_folder(client, folder_name, label_hint):
    print(f"\nChecking {folder_name}...")

    client.select_folder(folder_name, readonly=True)

    all_messages = client.search(["ALL"])
    unread_messages = client.search(["UNSEEN"])

    if unread_messages:
        messages = unread_messages
    else:
        messages = all_messages[-3:] if all_messages else []

    if not messages:
        print(f"No emails in {folder_name}")
        return

    fetched = client.fetch(messages, ["RFC822"])

    for uid, message_data in fetched.items():
        key = (folder_name, uid)

        if key in processed_uids:
            continue

        process_email(uid, message_data, folder_name, label_hint)
        processed_uids.add(key)


# ============================================================
# MAIN LOOP
# ============================================================

while True:
    try:
        print("\nChecking email folders...")

        with IMAPClient(IMAP_HOST) as client:
            client.login(EMAIL, PASSWORD)

            # Inbox
            scan_folder(client, "INBOX", "likely_legit")

            # Spam
            scan_folder(client, "[Gmail]/Spam", "likely_phishing")

        print(f"\nWaiting {CHECK_INTERVAL} seconds...")
        time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\nStopped by user.")
        break

    except Exception as e:
        print("\nError:", e)
        time.sleep(CHECK_INTERVAL)