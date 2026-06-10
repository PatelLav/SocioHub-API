"""Push notifications via Emergent-managed relay (SuprSend)."""

import logging
from datetime import datetime
from zoneinfo import ZoneInfo
from firebase_service import send_push
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from firebase_service import send_push

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


async def send_push(
    recipients: list[str],
    data: dict,
    idempotency_key: str | None = None,
) -> None:
    if not recipients:
        return
    if len(recipients) > 100:
        raise ValueError("max 100 recipients per /trigger call")
    if "title" not in data or "message" not in data:
        raise ValueError("data must include title and message")
    payload: dict = {"recipients": recipients, "data": data}
    if idempotency_key:
        payload["$idempotency_key"] = idempotency_key
    try:
        resp = await _client.post("/api/v1/push/trigger", json=payload)
        if resp.status_code == 401:
            log.error("EMERGENT_PUSH_KEY missing or invalid — push not delivered")
            return
        if resp.status_code >= 500:
            log.warning(f"Push provider 5xx ({resp.status_code})")
            return
        resp.raise_for_status()
    except httpx.HTTPError as e:
        log.warning(f"send_push HTTP error: {e}")


async def push_to_user(
    user: dict,
    pref_key: str,
    title: str,
    message: str,
    urgent: bool = False,
    action_url: str | None = None,
    idempotency_key: str | None = None,
) -> None:
    """Send a push to a single user, respecting preferences + quiet hours.

    pref_key examples: visitor_approvals_push, complaint_updates_push, new_notices_push, payment_reminders_push
    """
    try:
        if not _pref_allows(user, pref_key):
            return
        if _quiet_hours_blocks(user, urgent):
            return
        data = {"title": title, "message": message}
        if action_url:
            data["action_url"] = action_url
        token = user.get("fcm_token")

if token:
    await send_push(
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

            await send_push(
                token,
                title,
                message
            )
    except Exception as e:
        log.warning(f"push_to_users failed (non-blocking): {e}")
