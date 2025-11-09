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
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")

lock = threading.Lock()


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


def make_secret(bot_username: str) -> str:
    s = f"{bot_username}-{time.time()}-{os.urandom(8).hex()}"
    return hashlib.sha256(s.encode()).hexdigest()


def telegram_api_get(bot_token, path="getMe", params=None, timeout=10):
    url = f"https://api.telegram.org/bot{bot_token}/{path}"
    return requests.get(url, params=params, timeout=timeout)


def telegram_api_post(bot_token, path="setWebhook", params=None, timeout=15):
    url = f"https://api.telegram.org/bot{bot_token}/{path}"
    return requests.post(url, params=params, timeout=timeout)


@app.get("/")
def root():
    return jsonify(
        {
            "service": "robododark-gateway",
            "status": "ok",
            "notes": "use /v1/register to register bots",
        }
    )


@app.post("/v1/register")
def register():
    data = request.get_json(force=True, silent=True) or {}
    bot_token = data.get("bot_token", "").strip()
    forward_url = data.get("forward_url", "").strip()

    if not bot_token or not forward_url:
        return jsonify({"ok": False, "error": "missing bot_token or forward_url"}), 400

    # 1) valida token
    try:
        r = telegram_api_get(bot_token, "getMe", timeout=10)
    except Exception as e:
        return jsonify({"ok": False, "error": "telegram_getMe_failed", "detail": str(e)}), 502

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

    # 2) guarda no registry primeiro
    secret = make_secret(username)
    registry = load_registry()
    registry[username] = {
        "bot_token": bot_token,
        "forward_url": forward_url,
        "secret": secret,
        "registered_at": int(time.time()),
    }
    save_registry(registry)

    # 3) monta url pública do gateway
    if GATEWAY_BASE:
        gateway_base = GATEWAY_BASE.rstrip("/")
    else:
        gateway_base = request.url_root.rstrip("/")

    webhook_url = f"{gateway_base}/telegram/{username}"

    # 4) tenta setar no Telegram, mas não falha o registro
    params = {
        "url": webhook_url,
        "allowed_updates": ALLOWED_UPDATES,
        "secret_token": secret,
    }
    telegram_ok = True
    telegram_error_text = None
    try:
        set_r = telegram_api_post(bot_token, "setWebhook", params=params, timeout=15)
        if not set_r.ok:
            telegram_ok = False
            telegram_error_text = set_r.text
    except Exception as e:
        telegram_ok = False
        telegram_error_text = str(e)

    resp = {
        "ok": True,
        "bot_username": username,
        "secret": secret,
        "webhook": webhook_url,
        "forward_url": forward_url,
        "telegram_set_webhook": telegram_ok,
    }
    if not telegram_ok:
        resp["telegram_error"] = telegram_error_text

    return jsonify(resp), 200


@app.post("/telegram/<bot_username>")
def telegram_webhook(bot_username):
    registry = load_registry()
    entry = registry.get(bot_username)

    # fallback: se não achou no arquivo, tenta usar variável de ambiente fixa
    if not entry:
        fallback_url = os.getenv("FORWARD_FALLBACK_URL")
        if not fallback_url:
            return ("ignored", 404)
        # monta um entry fake só pra este request
        entry = {
            "forward_url": fallback_url,
            "secret": os.getenv("FALLBACK_SECRET", ""),  # opcional
        }

    # valida o secret do Telegram, se ele mandou
    header_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
    if header_secret and header_secret != entry.get("secret", ""):
        app.logger.warning("secret mismatch for %s", bot_username)
        return ("unauthorized", 401)

    callback = entry.get("forward_url")
    if not callback:
        return ("no callback", 500)

    payload = request.get_json(force=True, silent=True)

    try:
        headers = {
            "Content-Type": "application/json",
            "X-RoboDoDark-Secret": entry.get("secret", ""),
            "X-Forwarded-For": request.remote_addr or "",
        }
        requests.post(callback, json=payload, headers=headers, timeout=15)
    except Exception as e:
        app.logger.exception("forward failed")
        return (
            jsonify({"ok": False, "error": "forward_failed", "detail": str(e)}),
            502,
        )

    return ("OK", 200)


# ---------- NOVO: endpoint pra testar o forward de dentro do Render ----------
@app.post("/v1/test-forward")
def test_forward():
    """
    POST /v1/test-forward?bot=OmniSuperBot
    Tenta reenviar um JSON de teste para o forward_url salvo no registry.
    Útil pra ver se o Render consegue falar com o teu domínio.
    """
    bot = request.args.get("bot", "").strip()
    registry = load_registry()
    entry = registry.get(bot)
    if not entry:
        return jsonify({"ok": False, "error": "bot_not_found_in_registry"}), 404

    forward = entry.get("forward_url")
    if not forward:
        return jsonify({"ok": False, "error": "no_forward_url"}), 400

    test_payload = {
        "test": True,
        "source": "render-gateway",
        "bot": bot,
        "time": int(time.time()),
    }

    try:
        r = requests.post(
            forward,
            json=test_payload,
            headers={"Content-Type": "application/json", "X-RoboDoDark-Test": "1"},
            timeout=15,
        )
        return jsonify(
            {
                "ok": True,
                "forward_url": forward,
                "status_code": r.status_code,
                "text": r.text[:500],
            }
        ), 200
    except Exception as e:
        return jsonify(
            {
                "ok": False,
                "forward_url": forward,
                "error": "request_failed",
                "detail": str(e),
            }
        ), 200


@app.get("/v1/list")
def list_registrations():
    token = request.args.get("admin_token") or request.headers.get("X-Admin-Token")
    if ADMIN_TOKEN and token != ADMIN_TOKEN:
        return ("forbidden", 403)
    return jsonify(load_registry())


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "time": int(time.time())})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
