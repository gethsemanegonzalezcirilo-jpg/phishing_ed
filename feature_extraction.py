import pandas as pd
import numpy as np
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer

print("Loading parsed dataset...")

df = pd.read_csv("data\parsed_emails.csv")

df = df.dropna(subset=["cleaned_text", "label"])

vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=8000,
    ngram_range=(1, 2)
)

X = vectorizer.fit_transform(df["cleaned_text"])
y = df["label"].values

print("Feature matrix shape:", X.shape)

# Save dense matrix (since you're already doing that)
np.save("data/features.npy", X.toarray())
np.save("data/labels.npy", y)

with open("data/vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("Feature extraction complete.")