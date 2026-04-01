# ============================================================
# EMAIL INGESTION (FINAL - FULLY BALANCED + POLISHED)
# ============================================================

import time
import pickle
from imapclient import IMAPClient
import pyzmail

from parsing import clean_text, extract_rule_features, calculate_risk_score
from database import create_table, save_scan_result

EMAIL = "email.phishing.project@gmail.com"
PASSWORD = "tmahpvwiirnqczcd"
IMAP_HOST = "imap.gmail.com"

CHECK_INTERVAL = 30
FOLDERS = ["INBOX", "[Gmail]/Spam"]

TRUSTED_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "company.com"
]

def extract_domain(email_address):
    if "@" in email_address:
        return email_address.split("@")[-1].lower().strip()
    return ""

def is_trusted_sender(sender_email):
    return extract_domain(sender_email) in TRUSTED_DOMAINS

print("Loading model...")

with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("data/vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

create_table()
processed_uids = set()

print("System ready.")

while True:
    try:
        print("\nChecking email folders...")

        with IMAPClient(IMAP_HOST) as client:
            client.login(EMAIL, PASSWORD)

            for folder in FOLDERS:
                print(f"\n--- Scanning {folder} ---")
                client.select_folder(folder, readonly=True)

                messages = client.search(["UNSEEN"]) or client.search(["ALL"])[-5:]
                fetched = client.fetch(messages, ["RFC822"])

                for uid, message_data in fetched.items():
                    if uid in processed_uids:
                        continue

                    msg = pyzmail.PyzMessage.factory(message_data[b"RFC822"])

                    sender_email = "unknown"
                    from_addresses = msg.get_addresses("from")
                    if from_addresses:
                        _, sender_email = from_addresses[0]

                    subject = msg.get_subject() or "(No Subject)"

                    if msg.text_part:
                        body = msg.text_part.get_payload().decode(msg.text_part.charset or "utf-8", errors="ignore")
                    elif msg.html_part:
                        body = msg.html_part.get_payload().decode(msg.html_part.charset or "utf-8", errors="ignore")
                    else:
                        body = ""

                    full_text = f"{subject} {body}".strip()
                    if not full_text:
                        continue

                    cleaned = clean_text(full_text)
                    X = vectorizer.transform([cleaned])

                    prediction = model.predict(X)[0]
                    probs = model.predict_proba(X)[0]
                    confidence = float(max(probs))

                    f = extract_rule_features(full_text)

                    # ==============================
                    # BASE RISK
                    # ==============================
                    risk = calculate_risk_score(confidence, prediction, f)

                    # ==============================
                    # 🔥 FINAL BALANCED BOOSTS
                    # ==============================

                    if f["asks_for_credentials"]:
                        risk += 30

                    # Slightly reduced spoof weight
                    if f["advanced_domain_flag"] == 1:
                        risk += 18

                    if f["advanced_domain_flag"] == 2:
                        risk += 3

                    if f["social_engineering_score"] >= 2:
                        risk += 8

                    # Balanced data exfiltration
                    if f["data_exfiltration_score"] == 1:
                        risk += 12
                    if f["data_exfiltration_score"] >= 2:
                        risk += 15

                    if f["has_urgent_words"]:
                        risk += 5

                    # Reduced URL stacking
                    if f["has_url"] and not f["trusted_url"]:
                        risk += 3

                    # Trusted sender
                    if is_trusted_sender(sender_email):
                        risk -= 15

                    # 🔥 STRONG trusted brand reduction
                    trusted_keywords = ["google", "microsoft", "apple", "amazon"]

                    if any(word in full_text.lower() for word in trusted_keywords):
                        risk -= 25

                    # Business context reduction
                    if (
                        not f["has_url"]
                        and not f["asks_for_credentials"]
                        and f["data_exfiltration_score"] <= 1
                        and f["social_engineering_score"] <= 1
                    ):
                        risk -= 5

                    risk = max(0, min(risk, 100))

                    # ==============================
                    # LABEL
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

                    if f["data_exfiltration_score"] >= 1:
                        reasons.append("The email requests potentially sensitive data.")

                    if f["has_urgent_words"]:
                        reasons.append("The message uses urgency to pressure immediate action.")

                    if f["has_url"] and not f["trusted_url"]:
                        reasons.append("The email contains a link from an untrusted domain.")

                    if not reasons:
                        if label == "Legitimate":
                            reasons.append("No phishing indicators were detected in this email.")
                        else:
                            reasons.append("This email was flagged based on learned patterns from the detection model.")

                    reason_text = "; ".join(reasons)

                    save_scan_result({
                        "original_text": full_text,
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

                    print("\n--- EMAIL SCANNED ---")
                    print("Folder:", folder)
                    print("From:", sender_email)
                    print("Subject:", subject)
                    print("Prediction:", label)
                    print("Risk:", risk)

                    processed_uids.add(uid)

        time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("Stopped.")
        break

    except Exception as e:
        print("Error:", e)
        time.sleep(CHECK_INTERVAL)