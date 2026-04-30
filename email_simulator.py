import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
import random

# =========================
# CONFIG
# =========================
EMAIL = "email.phishing.project@gmail.com"
PASSWORD = "tmahpvwiirnqczcd"
TO_EMAIL = EMAIL

DELAY_BETWEEN_EMAILS = (2, 5)  # random delay range
TOTAL_EMAILS = 15  # how many to send

# =========================
# EMAIL POOLS
# =========================

legit_subjects = [
    "Project Update",
    "Meeting Follow-Up",
    "Weekly Report",
    "Team Reminder",
    "Invoice Attached"
]

legit_bodies = [
    "Hey team, I uploaded the latest file to SharePoint. Let me know your feedback.",
    "Just following up on today’s meeting. Let me know if anything needs to be updated.",
    "Please review the attached invoice when you have a moment.",
    "Reminder that deadlines are approaching this week.",
]

suspicious_subjects = [
    "Quick Request",
    "Need This Today",
    "File Access",
    "Can You Help?",
]

suspicious_bodies = [
    "Hey, can you send me the employee list when you get a chance?",
    "I uploaded the document here http://sharedocs-online.net/download please confirm access",
    "Can you send over the latest financial summary today?",
    "Let me know if you can help with this quickly.",
]

phishing_subjects = [
    "Account Verification Required",
    "Microsoft Security Alert",
    "Urgent Action Needed",
    "Your Account Will Be Suspended",
]

phishing_bodies = [
    "Your account has been flagged. Verify immediately at http://secure-account-check.com",
    "Unusual login attempt detected. Confirm here http://microsoft-authentication.net",
    "Your account will be restricted. Verify now at http://account-verification-hub.com",
    "Security alert. Login required at http://dropbox-secure-login.com",
]

# =========================
# SEND FUNCTION
# =========================

def send_email(subject, body):
    msg = MIMEMultipart()
    msg["From"] = EMAIL
    msg["To"] = TO_EMAIL
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.send_message(msg)

    print(f"Sent: {subject}")

# =========================
# GENERATOR
# =========================

def generate_email():
    email_type = random.choices(
        ["legit", "suspicious", "phishing"],
        weights=[0.4, 0.3, 0.3]
    )[0]

    if email_type == "legit":
        subject = random.choice(legit_subjects)
        body = random.choice(legit_bodies)

    elif email_type == "suspicious":
        subject = random.choice(suspicious_subjects)
        body = random.choice(suspicious_bodies)

    else:
        subject = random.choice(phishing_subjects)
        body = random.choice(phishing_bodies)

    return subject, body, email_type

# =========================
# RUN
# =========================

print("Starting email simulation...\n")

for i in range(TOTAL_EMAILS):
    subject, body, etype = generate_email()

    send_email(subject, body)

    print(f"Type: {etype.upper()}")
    print("-" * 40)

    time.sleep(random.uniform(*DELAY_BETWEEN_EMAILS))

print("\nSimulation complete.")