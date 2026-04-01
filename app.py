from flask import Flask, render_template, jsonify
from database import get_connection

app = Flask(__name__)

def get_all_results():
    with get_connection() as conn:
        conn.row_factory = lambda cursor, row: {
            "id": row[0],
            "text": row[1],
            "label": row[2],
            "confidence": row[3],
            "risk": row[4],
            "reasons": row[5] or "",
            "date": row[6]
        }

        cursor = conn.execute("""
            SELECT id, original_text, prediction_label,
                   model_confidence, risk_score,
                   flag_reasons, created_at
            FROM scan_results
            ORDER BY created_at DESC
        """)

        return cursor.fetchall()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    emails = get_all_results()
    return render_template("dashboard.html", emails=emails)

@app.route("/api/emails")
def api_emails():
    rows = get_all_results()
    return jsonify(rows)

@app.route("/email/<int:id>")
def detail(id):
    rows = get_all_results()
    email = next(e for e in rows if e["id"] == id)
    return render_template("detail.html", email=email)

if __name__ == "__main__":
    app.run(debug=True)