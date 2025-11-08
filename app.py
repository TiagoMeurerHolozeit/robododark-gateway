# app.py
import os
import json
import time
import threading
import hashlib
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

DATA_FILE = os.getenv("REGISTRY_FILE", "registry.json")
GATEWAY_BASE = os.getenv("GATEWAY_BASE")  # ex: https://robododark-gateway.onrender.com
ALLOWED_UPDATES = json.dumps(["message", "edited_message", "callback_query"])
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")  # opcional, pra /v1/list

lock = threading.Lock()


# ---------------- helpers ----------------
def load_registry():
    if not os.path.exists(DATA_FILE):
        return {}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_registry(r):
    with lock:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2, ensure_ascii=False)


def make_secret(bot_username):
    s = f"{bot_username}-{time.time()}-{os.urandom(8).hex()}"
    return hashlib.sha256(s.encode()).hexdigest()


def telegram_api_get(bot_token, path="getMe", params=None, timeout=10):
    url = f"https://api.telegram.org/bot{bot_token}/{path}"
    return requests.get(url, params=params, timeout=timeout)


def telegram_api_post(bot_token, path="setWebhook", params=None, timeout=15):
    url = f"https://api.telegram.org/bot{bot_token}/{path}"
    return requests.post(url, params=params, timeout=timeout)


# ---------------- endpoints ----------------
@app.route("/", methods=["GET"])
def root():
    return jsonify(
        {
            "service": "robododark-gateway",
            "status": "ok",
            "notes": "use /v1/register to register bots",
        }
    )


@app.route("/v1/register", methods=["POST"])
def register():
    """
    Body JSON:
      {
        "bot_token": "...",
        "forward_url": "http://127.0.0.1:5678/webhook/robododark_telegram"
      }
    Returns:
      { ok: true, bot_username, secret, webhook }
    """
    data = request.get_json(force=True, silent=True) or {}
    bot_token = data.get("bot_token")
    forward_url = data.get("forward_url")

    if not bot_token or not forward_url:
        return (
            jsonify({"ok": False, "error": "missing bot_token or forward_url"}),
            400,
        )

    # 1) valida token no Telegram
    try:
        r = telegram_api_get(bot_token, "getMe", timeout=10)
    except Exception as e:
        return (
            jsonify({"ok": False, "error": "telegram_getMe_failed", "detail": str(e)}),
            502,
        )

    if not r.ok:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "telegram_getMe_failed",
                    "telegram": r.text,
                }
            ),
            400,
        )

    info = r.json().get("result", {})
    username = info.get("username")
    if not username:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "could_not_determine_bot_username",
                    "telegram": r.text,
                }
            ),
            400,
        )

    # 2) gera segredo e salva
    secret = make_secret(username)
    registry = load_registry()
    registry[username] = {
        "bot_token": bot_token,
        "forward_url": forward_url,
        "secret": secret,
        "registered_at": int(time.time()),
    }
    save_registry(registry)

    # 3) monta URL pública deste gateway
    if GATEWAY_BASE:
        gateway_base = GATEWAY_BASE.rstrip("/")
    else:
        gateway_base = request.url_root.rstrip("/")

    webhook_url = f"{gateway_base}/telegram/{username}"

    # 4) registra o webhook no Telegram (AQUI estava o 400)
    #    o Telegram quer secret_token como param, não no JSON
    params = {
        "url": webhook_url,
        "allowed_updates": ALLOWED_UPDATES,
        "secret_token": secret,
    }

    try:
        set_r = telegram_api_post(bot_token, "setWebhook", params=params, timeout=15)
    except Exception as e:
        return (
            jsonify({"ok": False, "error": "setWebhook_failed", "detail": str(e)}),
            502,
        )

    if not set_r.ok:
        # devolve o erro do Telegram pra facilitar debug
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "telegram_setWebhook_failed",
                    "telegram": set_r.text,
                }
            ),
            400,
        )

    # 5) resposta final
    return jsonify(
        {
            "ok": True,
            "bot_username": username,
            "secret": secret,
            "webhook": webhook_url,
            "forward_url": forward_url,
        }
    )


@app.route("/telegram/<bot_username>", methods=["POST"])
def telegram_webhook(bot_username):
    registry = load_registry()
    entry = registry.get(bot_username)
    if not entry:
        return ("ignored", 404)

    # valida secret do Telegram
    header_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
    if header_secret and header_secret != entry.get("secret"):
        app.logger.warning("secret mismatch for %s", bot_username)
        return ("unauthorized", 401)

    callback = entry.get("forward_url")
    if not callback:
        return ("no callback", 500)

    payload = request.get_json(force=True, silent=True)

    try:
        headers = {
            "Content-Type": "application/json",
            "X-RoboDoDark-Secret": entry.get("secret"),
            "X-Forwarded-For": request.remote_addr or "",
        }
        forward_r = requests.post(
            callback, json=payload, headers=headers, timeout=15
        )
    except Exception as e:
        app.logger.exception("forward failed")
        return (
            jsonify({"ok": False, "error": "forward_failed", "detail": str(e)}),
            502,
        )

    return ("OK", 200)


@app.route("/v1/list", methods=["GET"])
def list_registrations():
    token = request.args.get("admin_token") or request.headers.get("X-Admin-Token")
    if ADMIN_TOKEN and token != ADMIN_TOKEN:
        return ("forbidden", 403)
    return jsonify(load_registry())


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True, "time": int(time.time())})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
