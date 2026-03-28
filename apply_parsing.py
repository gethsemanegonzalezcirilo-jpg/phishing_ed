# This script applies all text preprocessing and rule-based
# phishing feature extraction to the cleaned email dataset.
#
# PURPOSE:
#   1. Load the cleaned phishing email dataset
#   2. Generate an autocorrected version of each email
#   3. Generate a cleaned version of each email for ML use
#   4. Extract phishing rule features from each email
#   5. Generate human-readable flag reasons
#   6. Save the processed dataset for later Sprint 2 steps
#
# OUTPUT:
#   data/parsed_emails.csv
#
# This file will later be used by:
#   - feature_extraction.py
#   - train_model.py
#   - predict_local.py
# ============================================================

import pandas as pd

# Import functions from parsing.py
from parsing import (
    autocorrect_text,
    clean_text,
    extract_rule_features,
    get_flag_reasons,
)

# ------------------------------------------------------------
# STEP 1: Load cleaned dataset
#
# This file should already exist from Sprint 1 dataset prep.
# It contains the cleaned phishing email dataset.
# ------------------------------------------------------------

print("Loading cleaned dataset...")
df = pd.read_csv("cleaned_phishing_email.csv")

# ------------------------------------------------------------
# Show an example of the original email text
# This helps with debugging and screenshots for the demo.
# ------------------------------------------------------------

print("Original Email:")
print(str(df["message"].iloc[0])[:250])

# ------------------------------------------------------------
# STEP 2: Create autocorrected text
#
# This version fixes common phishing misspellings and
# obfuscation tricks like:
#   g00gle -> google
#   accnt  -> account
# ------------------------------------------------------------

df["autocorrected_text"] = df["message"].apply(autocorrect_text)

# ------------------------------------------------------------
# STEP 3: Create cleaned text
#
# This version is used for the machine learning model.
# It is lowercased and stripped of URLs, punctuation, etc.
# ------------------------------------------------------------

df["cleaned_text"] = df["message"].apply(clean_text)

# ------------------------------------------------------------
# STEP 4: Extract phishing rule features
#
# For each email, extract all phishing indicators from
# parsing.py and convert them into separate DataFrame columns.
#
# Example rule features:
#   has_url
#   has_urgent_words
#   asks_for_credentials
#   brand_impersonation
#   suspicious_tld
# ------------------------------------------------------------

rule_features = df["message"].apply(extract_rule_features).apply(pd.Series)

# Merge the extracted feature columns back into the main DataFrame
df = pd.concat([df, rule_features], axis=1)

# ------------------------------------------------------------
# STEP 5: Generate human-readable flag reasons
#
# These are the explanations shown in the output and stored
# in the database.
#
# Example:
#   "Contains URL or domain; Uses urgent language"
# ------------------------------------------------------------

df["flag_reasons"] = df.apply(
    lambda row: "; ".join(
        get_flag_reasons(
            {
                "has_url": row["has_url"],
                "has_urgent_words": row["has_urgent_words"],
                "asks_for_credentials": row["asks_for_credentials"],
                "has_click_language": row["has_click_language"],
                "suspicious_symbol_count": row["suspicious_symbol_count"],
                "uppercase_ratio": row["uppercase_ratio"],
                "typo_suspicion_score": row["typo_suspicion_score"],
                "brand_impersonation": row["brand_impersonation"],
                "subdomain_phishing": row["subdomain_phishing"],
                "homoglyph_attack": row["homoglyph_attack"],
                "suspicious_tld": row["suspicious_tld"],
            }
        )
    ),
    axis=1,
)

# ------------------------------------------------------------
# STEP 6: Print samples for review
#
# These outputs help verify that the script is working and are
# useful for screenshots in your presentation.
# ------------------------------------------------------------

print("\nAutocorrected Email:")
print(str(df["autocorrected_text"].iloc[0])[:250])

print("\nCleaned Email:")
print(str(df["cleaned_text"].iloc[0])[:250])

print("\nRule Feature Preview:")
print(
    df[
        [
            "has_url",
            "has_urgent_words",
            "asks_for_credentials",
            "has_click_language",
            "typo_suspicion_score",
            "brand_impersonation",
            "subdomain_phishing",
            "homoglyph_attack",
            "suspicious_tld",
            "flag_reasons",
        ]
    ].head()
)

# ------------------------------------------------------------
# STEP 7: Save processed dataset
#
# This CSV is the main parsed dataset used in the next steps of
# Sprint 2.
# ------------------------------------------------------------

df.to_csv("data/parsed_emails.csv", index=False)

print("Parsing + phishing feature engineering complete.")