# ============================================================
# init_db.py
#
# This script initializes the SQLite database for the project.
#
# PURPOSE:
#   - Call create_table() from database.py
#   - Ensure the scan_results table exists before running
#     phishing predictions
#
# HOW TO RUN:
#   py init_db.py
#
# OUTPUT:
#   scan_results.db file
#   scan_results table
#
# This only needs to be run once initially, but it is safe to
# run multiple times because CREATE TABLE IF NOT EXISTS is used.
# ============================================================

from database import create_table


# ------------------------------------------------------------
# Create the database table
# ------------------------------------------------------------

create_table()

print("Database initialized successfully: scan_results.db")