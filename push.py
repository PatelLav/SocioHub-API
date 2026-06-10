"""Push notifications via Emergent-managed relay (SuprSend)."""

import logging
from datetime import datetime
from zoneinfo import ZoneInfo
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from firebase_service import firebase_send_push

log = logging.getLogger("sociohub.push")

push_router = APIRouter(prefix="/api")

IST = ZoneInfo("Asia/Kolkata")


class RegisterPushBody(BaseModel):
    user_id: str
    platform: str
    device_token: str


@push_router.post("/register-push")
async def register_push(body: RegisterPushBody):

    from server import db

    await db.users.update_one(
        {"id": body.user_id},
        {
            "$set": {
                "fcm_token": body.device_token,
                "platform": body.platform
            }
        }
    )

    return {"status": "registered"}

def _is_quiet_hours(now: datetime | None = None) -> bool:
    now = (now or datetime.now(IST)).astimezone(IST)
    h = now.hour
    return h >= 22 or h < 7  # 10 PM – 7 AM IST


def _pref_allows(user: dict, pref_key: str) -> bool:
    """Check if user.preferences.notifications.<pref_key> is enabled (default True)."""
    prefs = (user.get("preferences") or {}).get("notifications") or {}
    return bool(prefs.get(pref_key, True))


def _quiet_hours_blocks(user: dict, urgent: bool) -> bool:
    if urgent:
        return False
    prefs = (user.get("preferences") or {}).get("notifications") or {}
    if not prefs.get("quiet_hours_enabled", True):
        return False
    return _is_quiet_hours()


async def push_to_user(
    user: dict,
    pref_key: str,
    title: str,
    message: str,
    urgent: bool = False,
    action_url: str | None = None,
    idempotency_key: str | None = None,
) -> None:
    try:
        if not _pref_allows(user, pref_key):
            return

        if _quiet_hours_blocks(user, urgent):
            return

        token = user.get("fcm_token")

        if token:
            await firebase_send_push(
                token,
                title,
                message
            )

    except Exception as e:
        log.warning(f"push_to_user failed (non-blocking): {e}")

async def push_to_users(
    users: list[dict],
    pref_key: str,
    title: str,
    message: str,
    urgent: bool = False,
    action_url: str | None = None,
    idempotency_key: str | None = None,
) -> None:
    try:
        eligible = [u["id"] for u in users
                    if _pref_allows(u, pref_key) and not _quiet_hours_blocks(u, urgent)]
        if not eligible:
            return
        data = {"title": title, "message": message}
        if action_url:
            data["action_url"] = action_url
        # Chunk by 100
        for u in users:

            token = u.get("fcm_token")

            if not token:
                continue

            await firebase_send_push(
                token,
                title,
                message
            )
    except Exception as e:
        log.warning(f"push_to_users failed (non-blocking): {e}")
