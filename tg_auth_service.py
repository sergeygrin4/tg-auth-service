import os
import logging
import asyncio

from flask import Flask, request, jsonify
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tg_auth_service")

app = Flask(__name__)

# ---- Настройки ----
API_ID = int(os.getenv("TG_API_ID", "34487940"))
API_HASH = os.getenv("TG_API_HASH", "6f1242a8c3796d44fb761364b35a83f0")

# Токен для авторизации запросов от миниаппа
AUTH_TOKEN = os.getenv("TG_AUTH_SERVICE_TOKEN", "super-secret-token")

# В памяти храним phone_code_hash по телефону
pending_codes: dict[str, str] = {}  # phone -> phone_code_hash


def check_auth() -> bool:
    token = request.headers.get("X-AUTH-TOKEN") or ""
    return token == AUTH_TOKEN


# ---- Async-хелперы ----

async def _send_code(phone: str) -> str:
    """
    Отправить код на телефон через Telethon, вернуть phone_code_hash.
    """
    client = TelegramClient(StringSession(), API_ID, API_HASH)
    await client.connect()
    try:
        result = await client.send_code_request(phone)
        phone_code_hash = result.phone_code_hash
        logger.info(
            "send_code_request OK for %s: phone_code_hash=%s, result=%r",
            phone,
            phone_code_hash,
            result,
        )
        return phone_code_hash
    finally:
        await client.disconnect()


async def _sign_in(phone: str, code: str, phone_code_hash: str, password: str | None) -> str:
    """
    Подтвердить код, вернуть StringSession.
    """
    session = StringSession()
    client = TelegramClient(session, API_ID, API_HASH)
    await client.connect()
    try:
        try:
            await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
        except SessionPasswordNeededError:
            if not password:
                raise
            await client.sign_in(password=password)

        session_str = session.save()
        logger.info("sign_in OK for %s, session length=%d", phone, len(session_str))
        return session_str
    finally:
        await client.disconnect()


# ---- HTTP-эндпоинты ----

@app.route("/auth/start", methods=["POST"])
def auth_start():
    """
    Шаг 1: отправить код.
    Тело: {"phone": "+7999..."}
    """
    if not check_auth():
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "phone_required"}), 400

    try:
        phone_code_hash = asyncio.run(_send_code(phone))
    except Exception as e:
        logger.exception("auth_start error")
        return jsonify({"error": str(e)}), 500

    pending_codes[phone] = phone_code_hash
    return jsonify({"status": "ok"})


@app.route("/auth/confirm", methods=["POST"])
def auth_confirm():
    """
    Шаг 2: подтвердить код, получить StringSession.
    Тело: {"phone": "+7999...", "code": "12345", "password": "optional"}
    """
    if not check_auth():
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    code = (data.get("code") or "").strip()
    password = (data.get("password") or "").strip() or None

    if not phone:
        return jsonify({"error": "phone_required"}), 400
    if not code:
        return jsonify({"error": "code_required"}), 400

    phone_code_hash = pending_codes.get(phone)
    if not phone_code_hash:
        return jsonify({"error": "no_pending_code_for_phone"}), 400

    try:
        session_str = asyncio.run(_sign_in(phone, code, phone_code_hash, password))
    except Exception as e:
        logger.exception("auth_confirm error")
        return jsonify({"error": str(e)}), 500

    pending_codes.pop(phone, None)

    return jsonify({"status": "ok", "session": session_str})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    logger.info("Starting tg_auth_service on port %s", port)
    app.run(host="0.0.0.0", port=port)
