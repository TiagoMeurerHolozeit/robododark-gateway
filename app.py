import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# URL do robô local (na máquina do usuário) para onde o gateway vai repassar
LOCAL_API_URL = os.getenv("LOCAL_API_URL", "http://localhost:8000/transcribe")

# opcional: token de segurança simples
SECRET_TOKEN = os.getenv("SECRET_TOKEN")

@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "robododark-gateway",
        "status": "ok",
        "forward_to": LOCAL_API_URL
    })

@app.route("/webhook/telegram", methods=["POST"])
def telegram_webhook():
    # se quiser travar com segredo
    if SECRET_TOKEN:
        header_token = request.headers.get("X-Gateway-Token")
        if header_token != SECRET_TOKEN:
            return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    # repassa para o robô local
    try:
        resp = requests.post(LOCAL_API_URL, json=data, timeout=5)
        return jsonify({
            "ok": True,
            "local_status": resp.status_code,
            "local_response": resp.text
        }), 200
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
            "forward_to": LOCAL_API_URL
        }), 500


# Render usa a variável PORT
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
