from transformers import pipeline
from parsing import clean_text

print("Loading pretrained phishing classifier...")

classifier = pipeline(
    "text-classification",
    model="ealvaradob/bert-finetuned-phishing"
)

while True:
    text = input("\nEnter an email (or type 'exit'): ")

    if text.lower() == "exit":
        break

    cleaned = clean_text(text)
    result = classifier(cleaned)

    print("Prediction:", result[0]['label'])
    print("Confidence:", round(result[0]['score'], 4))