# ============================================================
# database.py
#
# This file handles all SQLite database operations for the
# phishing email detector project.
#
# PURPOSE:
#   1. Connect to the SQLite database
#   2. Create the scan_results table if it does not exist
#   3. Save phishing scan results into the database
#
# WHY THIS MATTERS:
# Security tools usually keep a record of detections for:
#   - auditing
#   - reporting
#   - review
#   - trend analysis
#
# In this project, every tested email is stored in a local
# SQLite database file called:
#
#   scan_results.db
#
# This database stores:
#   - original email text
#   - cleaned text
#   - prediction result
#   - confidence score
#   - risk score
#   - phishing rule flags
#   - timestamp
# ============================================================

import sqlite3
from pathlib import Path


# ------------------------------------------------------------
# DATABASE FILE PATH
#
# This is the local SQLite database file used by the project.
# If the file does not exist yet, SQLite will create it.
# ------------------------------------------------------------

DB_PATH = Path("scan_results.db")


# ------------------------------------------------------------
# get_connection()
#
# PURPOSE:
# Create and return a connection to the SQLite database.
#
# RETURNS:
#   sqlite3.Connection object
# ------------------------------------------------------------

def get_connection():
    return sqlite3.connect(DB_PATH)


# ------------------------------------------------------------
# create_table()
#
# PURPOSE:
# Create the scan_results table if it does not already exist.
#
# This table stores one row for each email scan.
#
# TABLE COLUMNS:
#   id                       -> unique record ID
#   original_text            -> raw user input
#   autocorrected_text       -> typo-normalized text
#   cleaned_text             -> ML-ready cleaned text
#   prediction_label         -> phishing / legitimate / insufficient
#   model_confidence         -> ML confidence score
#   risk_score               -> final phishing risk score (0-100)
#   has_url                  -> URL/domain detected
#   has_urgent_words         -> urgent wording detected
#   asks_for_credentials     -> credential request detected
#   suspicious_symbol_count  -> count of suspicious symbols
#   uppercase_ratio          -> ratio of uppercase letters
#   flag_reasons             -> readable phishing explanations
#   created_at               -> timestamp of the scan
# ------------------------------------------------------------

def create_table():
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_text TEXT NOT NULL,
                autocorrected_text TEXT,
                cleaned_text TEXT,
                prediction_label TEXT NOT NULL,
                model_confidence REAL NOT NULL,
                risk_score INTEGER NOT NULL,
                has_url INTEGER NOT NULL,
                has_urgent_words INTEGER NOT NULL,
                asks_for_credentials INTEGER NOT NULL,
                suspicious_symbol_count INTEGER NOT NULL,
                uppercase_ratio REAL NOT NULL,
                flag_reasons TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


# ------------------------------------------------------------
# save_scan_result(result)
#
# PURPOSE:
# Insert one phishing scan result into the scan_results table.
#
# PARAMETERS:
#   result : dict
#       A dictionary containing all scan output values
#
# EXPECTED KEYS:
#   original_text
#   autocorrected_text
#   cleaned_text
#   prediction_label
#   model_confidence
#   risk_score
#   has_url
#   has_urgent_words
#   asks_for_credentials
#   suspicious_symbol_count
#   uppercase_ratio
#   flag_reasons
#
# RETURNS:
#   None
# ------------------------------------------------------------

def save_scan_result(result: dict):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_results (
                original_text,
                autocorrected_text,
                cleaned_text,
                prediction_label,
                model_confidence,
                risk_score,
                has_url,
                has_urgent_words,
                asks_for_credentials,
                suspicious_symbol_count,
                uppercase_ratio,
                flag_reasons
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["original_text"],
                result["autocorrected_text"],
                result["cleaned_text"],
                result["prediction_label"],
                result["model_confidence"],
                result["risk_score"],
                result["has_url"],
                result["has_urgent_words"],
                result["asks_for_credentials"],
                result["suspicious_symbol_count"],
                result["uppercase_ratio"],
                result["flag_reasons"],
            ),
        )
        conn.commit()