from flask import Flask, request, jsonify
import requests, os

app = Flask(__name__)

# ===== Configuração base =====
LOCAL_API_URL = os.getenv("LOCAL_API_URL", "http://localhost:8000/transcribe")  # exemplo local

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "ok", "service": "RoboDoDark Gateway"}), 200

@app.route("/webhook/robododark_telegram", methods=["POST"])
def telegram_webhook():
    data = request.json
    if not data:
        return jsonify({"error": "empty request"}), 400

    # Exemplo: repassa o payload para o endpoint local (FastAPI/n8n)
    try:
        r = requests.post(LOCAL_API_URL, json=data, timeout=10)
        return jsonify({"ok": True, "local_response": r.text}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
