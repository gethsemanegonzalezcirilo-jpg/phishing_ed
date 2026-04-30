from database import get_connection, create_table
import random
from datetime import datetime

create_table()

print("\n🔧 Resetting demo data...\n")

with get_connection() as conn:
    conn.execute("DELETE FROM scan_results")
    conn.execute("DELETE FROM trusted_domains")
    conn.execute("DELETE FROM blocked_domains")
    conn.commit()

print("📥 Inserting realistic demo emails...\n")

# 🔴 malicious domains (REPEATED for demo impact)
malicious_domains = [
    "secure-paypal-alert.com",
    "chase-verification.net"
]

# 🟢 safe domains
safe_domains = [
    "paypal.com",
    "company.com"
]

phishing_texts = [
    "URGENT: Verify your account now http://fake-link.com",
    "Your account will be locked. Login immediately",
    "Suspicious login detected, confirm credentials now"
]

safe_texts = [
    "Weekly report attached",
    "Meeting scheduled for tomorrow",
    "Invoice processed successfully"
]

with get_connection() as conn:

    # 🔴 MALICIOUS → QUARANTINE
    for domain in malicious_domains:
        for i in range(3):  # repeat = strong demo
            conn.execute("""
                INSERT INTO scan_results (
                    original_text, sender, subject,
                    prediction_label, model_confidence,
                    risk_score, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                random.choice(phishing_texts),
                f"user{i}@{domain}",
                "Security Alert",
                "Suspicious",
                0.9,
                random.randint(60, 85),
                "quarantine"
            ))

    # 🟢 SAFE → APPROVED
    for domain in safe_domains:
        for i in range(2):
            conn.execute("""
                INSERT INTO scan_results (
                    original_text, sender, subject,
                    prediction_label, model_confidence,
                    risk_score, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                random.choice(safe_texts),
                f"employee{i}@{domain}",
                "Normal Activity",
                "Legitimate",
                0.95,
                random.randint(5, 20),
                "approved"
            ))

    conn.commit()

print("✅ Demo data inserted!\n")

# ==========================================
# OPTIONAL: SHOW BEFORE
# ==========================================
print("📊 CURRENT STATE:\n")

with get_connection() as conn:
    rows = conn.execute("""
        SELECT sender, risk_score, status FROM scan_results
    """).fetchall()

for r in rows:
    print(r)

print("\n👉 Open your dashboard and run your demo")