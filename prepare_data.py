import pandas as pd
import re

print("Loading dataset...")
df = pd.read_csv("data/phishing_email.csv")

print("Columns:")
print(df.columns)

# Rename column to standard name
df = df.rename(columns={'text_combined': 'message'})

# Keep only what we need
df = df[['message', 'label']]

# ----------------------------
# CLEANING FUNCTION
# ----------------------------

def clean_text(text):
    text = str(text).lower()                      # lowercase
    text = re.sub(r"http\S+", "", text)           # remove URLs
    text = re.sub(r"\d+", "", text)               # remove numbers
    text = re.sub(r"[^\w\s]", "", text)           # remove punctuation
    text = re.sub(r"\s+", " ", text).strip()      # remove extra spaces
    return text

print("Cleaning text...")
df['message'] = df['message'].apply(clean_text)

# Remove empty rows
df = df[df['message'].str.strip() != ""]

# Save cleaned dataset
output_file = "cleaned_phishing_email.csv"
df.to_csv(output_file, index=False)

print(f"Cleaned dataset saved as {output_file}")
print("Done.")