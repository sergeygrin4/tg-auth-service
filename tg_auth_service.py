import os
import logging
import asyncio
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneCodeExpiredError,
    PhoneNumberBannedError,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tg_auth_service")

app = Flask("tg_auth_service")

# ======================= ENV =======================

API_ID = int(os.getenv("TG_API_ID") or os.getenv("API_ID") or "0")
API_HASH = os.getenv("TG_API_HASH") or os.getenv("API_HASH") or ""

AUTH_TOKEN = os.getenv("AUTH_TOKEN") or os.getenv("TG_AUTH_SERVICE_TOKEN") or ""

PORT = int(os.getenv("PORT") or "8080")

PENDING_TTL_SECONDS = int(os.getenv("PENDING_TTL_SECONDS") or "600")  # 10 минут

if not API_ID or not API_HASH:
    logger.warning("TG_API_ID / TG_API_HASH are not configured!")

# phone_norm -> {phone, phone_code_hash, created_at}
_pending: dict[str, dict] = {}

# ======================= ВСПОМОГАТЕЛЬНЫЕ =======================


def _norm_phone(phone: str) -> str:
    phone = (phone or "").strip()
    if not phone:
        return ""
    if not phone.startswith("+"):
        if phone.startswith("8"):
            phone = "+7" + phone[1:]
        elif phone[0].isdigit():
            phone = "+" + phone
    return phone


def _check_auth(req: request) -> bool:
    if not AUTH_TOKEN:
        logger.warning("AUTH_TOKEN is not configured, denying all")
        return False
    hdr = req.headers.get("Authorization") or ""
    if not hdr.startswith("Bearer "):
        return False
    token = hdr[len("Bearer ") :].strip()
    return token == AUTH_TOKEN


def _cleanup_pending():
    if not _pending:
        return
    now = datetime.now(timezone.utc)
    to_del = []
    for phone, data in _pending.items():
        ts = data.get("created_at")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except Exception:
                ts = None
        if not ts:
            to_del.append(phone)
            continue
        if now - ts > timedelta(seconds=PENDING_TTL_SECONDS):
            to_del.append(phone)
    for phone in to_del:
        _pending.pop(phone, None)


async def _send_code_async(phone_norm: str) -> str:
    """
    Асинхронно отправляем код. ВАЖНО: не вызываем client.start(),
    только connect() / disconnect(), чтобы Telethon не просил input().
    """
    client = TelegramClient(StringSession(), API_ID, API_HASH)
    await client.connect()
    try:
        logger.info("send_code_request for %s", phone_norm)
        res = await client.send_code_request(phone_norm)
        phone_code_hash = res.phone_code_hash
        _pending[phone_norm] = {
            "phone": phone_norm,
            "phone_code_hash": phone_code_hash,
            "created_at": datetime.now(timezone.utc).replace(tzinfo=timezone.utc).isoformat(),
        }
        logger.info(
            "send_code_request OK for %s: phone_code_hash=%s, result=%r",
            phone_norm,
            phone_code_hash,
            res,
        )
        return phone_code_hash
    finally:
        await client.disconnect()


async def _confirm_code_async(phone_norm: str, code: str, password: str | None):
    """
    Асинхронно подтверждаем код и выдаём StringSession.
    Тоже без client.start(), только connect() / disconnect().
    """
    _cleanup_pending()
    data = _pending.get(phone_norm)
    if not data:
        raise ValueError("no_pending_code")

    phone_code_hash = data.get("phone_code_hash")
    if not phone_code_hash:
        raise ValueError("no_phone_code_hash")

    client = TelegramClient(StringSession(), API_ID, API_HASH)
    await client.connect()
    try:
        logger.info("sign_in for %s with code", phone_norm)
        try:
            await client.sign_in(
                phone=phone_norm,
                code=code,
                phone_code_hash=phone_code_hash,
            )
        except SessionPasswordNeededError:
            if not password:
                logger.warning("2FA password required for %s but not provided", phone_norm)
                raise
            logger.info("2FA password provided for %s, signing in with password", phone_norm)
            await client.sign_in(password=password)

        me = await client.get_me()
        session_str = client.session.save()
        logger.info("sign_in OK for %s, username=%s", phone_norm, getattr(me, "username", None))
    finally:
        await client.disconnect()

    _pending.pop(phone_norm, None)
    return session_str, me


# ======================= ROUTES =======================


@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "tg_auth_service", "status": "ok"}), 200


@app.route("/auth/start", methods=["POST"])
def auth_start():
    """Шаг 1: отправка кода по номеру."""
    if not _check_auth(request):
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    phone = data.get("phone") or ""
    phone_norm = _norm_phone(phone)
    if not phone_norm:
        return jsonify({"error": "phone_required"}), 400

    if not API_ID or not API_HASH:
        logger.error("API_ID / API_HASH not configured")
        return jsonify({"error": "api_not_configured"}), 500

    try:
        phone_code_hash = asyncio.run(_send_code_async(phone_norm))
        return jsonify({"ok": True, "phone_code_hash": phone_code_hash}), 200
    except PhoneNumberBannedError:
        logger.exception("PhoneNumberBannedError for %s", phone_norm)
        return jsonify({"error": "phone_banned"}), 400
    except EOFError as e:
        logger.exception("EOFError in auth_start for %s: %s", phone_norm, e)
        return jsonify({"error": "internal_error", "details": "eof_in_library"}), 500
    except Exception as e:
        logger.exception("auth_start failed for %s: %s", phone_norm, e)
        return jsonify({"error": "internal_error", "details": str(e)}), 500


@app.route("/auth/confirm", methods=["POST"])
def auth_confirm():
    """Шаг 2: подтверждение кода, возврат StringSession."""
    if not _check_auth(request):
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    phone = data.get("phone") or ""
    code = (data.get("code") or "").strip()
    password = data.get("password") or None

    phone_norm = _norm_phone(phone)
    if not phone_norm or not code:
        return jsonify({"error": "phone_and_code_required"}), 400

    if not API_ID or not API_HASH:
        logger.error("API_ID / API_HASH not configured")
        return jsonify({"error": "api_not_configured"}), 500

    try:
        session_str, me = asyncio.run(_confirm_code_async(phone_norm, code, password))
        return (
            jsonify(
                {
                    "ok": True,
                    "session": session_str,
                    "me": {
                        "id": me.id,
                        "username": me.username,
                        "first_name": me.first_name,
                        "last_name": me.last_name,
                    },
                }
            ),
            200,
        )
    except SessionPasswordNeededError:
        return jsonify({"error": "2fa_password_required"}), 400
    except PhoneCodeInvalidError:
        return jsonify({"error": "code_invalid"}), 400
    except PhoneCodeExpiredError:
        return jsonify({"error": "code_expired"}), 400
    except ValueError as e:
        if str(e) in ("no_pending_code", "no_phone_code_hash"):
            return jsonify({"error": "no_pending_code"}), 400
        logger.exception("ValueError in auth_confirm: %s", e)
        return jsonify({"error": "internal_error", "details": str(e)}), 500
    except EOFError as e:
        logger.exception("EOFError in auth_confirm for %s: %s", phone_norm, e)
        return jsonify({"error": "internal_error", "details": "eof_in_library"}), 500
    except Exception as e:
        logger.exception("auth_confirm failed for %s: %s", phone_norm, e)
        return jsonify({"error": "internal_error", "details": str(e)}), 500


# ======================= MAIN =======================

if __name__ == "__main__":
    logger.info("Starting tg_auth_service on port %s", PORT)
    app.run(host="0.0.0.0", port=PORT)
