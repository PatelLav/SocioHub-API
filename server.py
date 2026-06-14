"""SocioHub Backend - Society Management SaaS API (v2 with Admin, Guard, Referrals)"""
import os
import uuid
import random
import string
import logging
import certifi
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Literal

from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr
from jose import jwt, JWTError
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

from push import push_router, push_to_user, push_to_users  # noqa: E402

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ.get("JWT_SECRET", "sociohub-dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_EXP_MIN = 60 * 24 * 7
OTP_EXP_MIN = 5
REFERRAL_CREDIT = 500.0  # ₹500 maintenance credit per successful referral

client = AsyncIOMotorClient(
    MONGO_URL,
    tlsCAFile=certifi.where()
)
db = client[DB_NAME]

app = FastAPI(title="SocioHub API v2")
api = APIRouter(prefix="/api")
bearer = HTTPBearer(auto_error=False)
log = logging.getLogger("sociohub")
logging.basicConfig(level=logging.INFO)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


def gen_ref_code(name: str) -> str:
    prefix = "".join(c for c in name.upper() if c.isalpha())[:4] or "USER"
    suffix = "".join(random.choices(string.digits, k=3))
    return f"{prefix}{suffix}"

def gen_invite_code(name: str):
    prefix = "".join(
        c for c in name.upper()
        if c.isalpha()
    )[:4]

    if not prefix:
        prefix = "SOCI"

    suffix = "".join(
        random.choices(
            string.digits,
            k=3
        )
    )

    return f"{prefix}{suffix}"
# ---- Models ----
class SignupIn(BaseModel):
    mobile: str = Field(..., min_length=10, max_length=15)
    name: str
    email: EmailStr
    flat_no: str
    tower: str = "A"
    referral_code: Optional[str] = None  # NEW


class LoginIn(BaseModel):
    mobile: str


class VerifyOtpIn(BaseModel):
    mobile: str
    otp: str


class UserOut(BaseModel):
    id: str
    mobile: str
    name: str
    email: str
    tenant_id: str
    tenant_name: str
    flat_no: str
    tower: str
    role: str
    avatar: Optional[str] = None
    referral_code: Optional[str] = None
    referral_credit: float = 0.0


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class VerifyOtpOut(BaseModel):
    is_registered: bool
    token: Optional[TokenOut] = None
    user: Optional[UserOut] = None
    mobile: Optional[str] = None


class VisitorIn(BaseModel):
    name: str
    mobile: str
    purpose: str
    visitor_type: Literal["guest", "delivery", "maid", "driver", "vendor"] = "guest"
    photo_base64: Optional[str] = None
    expected_at: Optional[datetime] = None
    flat_no: Optional[str] = None  # for guard walk-in: which flat


class VisitorActionIn(BaseModel):
    action: Literal["approve", "reject", "checkin", "checkout"]


class ComplaintIn(BaseModel):
    category: Literal["water", "electricity", "lift", "security", "cleaning", "parking"]
    description: str
    priority: Literal["low", "medium", "high"] = "medium"
    image_base64: Optional[str] = None


class ComplaintUpdateIn(BaseModel):
    status: Optional[Literal["open", "in_progress", "resolved", "closed"]] = None
    assigned_to: Optional[str] = None
    note: Optional[str] = None


class NoticeIn(BaseModel):
    title: str
    body: str
    category: Literal["general", "events", "emergency", "maintenance"] = "general"


class ResidentIn(BaseModel):
    mobile: str
    name: str
    email: EmailStr
    tower_id: str
    unit_id: str


class ResidentUpdateIn(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    flat_no: Optional[str] = None
    tower: Optional[str] = None


class PayIn(BaseModel):
    invoice_id: str


class PreferencesIn(BaseModel):
    privacy: Optional[dict] = None
    notifications: Optional[dict] = None

class SocietySearchOut(BaseModel):
    id: str
    name: str
    city: Optional[str] = None


class RegistrationRequestIn(BaseModel):
    tenant_id: str
    tower_id: str
    unit_id: str

    name: str
    mobile: str
    email: EmailStr

    invite_code: str


class RegistrationRequestActionIn(BaseModel):
    reason: Optional[str] = None


class TowerCreateIn(BaseModel):
    tenant_id: str
    name: str


class UnitCreateIn(BaseModel):
    tenant_id: str
    tower_id: str
    unit_no: str
class TenantCreateIn(BaseModel):
    name: str
    address: str
    city: str


class RegistrationApproveOut(BaseModel):
    success: bool
    message: str
class SocietyAdminCreateIn(BaseModel):
    tenant_id: str
    name: str
    mobile: str
    email: EmailStr
class CreateSocietyAdminIn(BaseModel):
    tenant_id: str
    name: str
    mobile: str
    email: str

class BulkUnitIn(BaseModel):
    tenant_id: str
    tower_id: str
    prefix: str
    start: int
    end: int

DEFAULT_PREFS = {
    "privacy": {
        "show_mobile_to_neighbours": False,
        "auto_delete_visitor_photos": True,
        "allow_data_export": True,
        "share_complaint_publicly": False,
    },
    "notifications": {
        "visitor_approvals_push": True,
        "visitor_approvals_sms": False,
        "complaint_updates_push": True,
        "complaint_updates_email": False,
        "payment_reminders_push": True,
        "payment_reminders_email": True,
        "new_notices_push": True,
        "quiet_hours_enabled": True,
    },
}


# ---- Auth helpers ----
def make_token(uid: str) -> str:
    return jwt.encode(
        {"sub": uid, "exp": now_utc() + timedelta(minutes=ACCESS_EXP_MIN), "iat": now_utc()},
        JWT_SECRET, algorithm=JWT_ALG,
    )


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    if not creds:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError:
        raise HTTPException(401, "Invalid token")
    user = await db.users.find_one({"id": payload.get("sub")}, {"_id": 0})
    if not user:
        raise HTTPException(401, "User not found")
    return user


def require_role(*roles: str):
    async def dep(user=Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(403, f"Requires role: {', '.join(roles)}")
        return user
    return dep


async def user_to_out(user: dict) -> UserOut:
    tenant_id = user.get("tenant_id")

    tenant_name = user.get("tenant_name")

    if tenant_id and not tenant_name:
        tenant = await db.tenants.find_one(
            {"id": tenant_id},
            {"_id": 0}
        )

        if tenant:
            tenant_name = tenant["name"]

    return UserOut(
        id=user["id"],
        mobile=user["mobile"],
        name=user["name"],
        email=user["email"],

        tenant_id=tenant_id or "",
        tenant_name=tenant_name or "",

        flat_no=user.get("flat_no", ""),
        tower=user.get("tower", ""),
        role=user.get("role", "resident"),
        avatar=user.get("avatar"),

        referral_code=user.get("referral_code"),
        referral_credit=user.get("referral_credit", 0.0),
    )


# ---- Auth Routes ----
@api.post("/auth/signup")
async def signup(payload: SignupIn):
    tenant = await db.tenants.find_one({}, {"_id": 0})
    existing = await db.users.find_one({"mobile": payload.mobile})
    if not existing:
        ref_code = gen_ref_code(payload.name)
        # ensure unique
        while await db.users.find_one({"referral_code": ref_code}):
            ref_code = gen_ref_code(payload.name)
        user_doc = {
            "id": new_id(), "mobile": payload.mobile, "name": payload.name, "email": payload.email,
            "tenant_id": tenant["id"], "flat_no": payload.flat_no, "tower": payload.tower,
            "role": "resident", "is_active": False, "avatar": None,
            "referral_code": ref_code, "referred_by_code": payload.referral_code,
            "referral_credit": 0.0, "created_at": now_utc(),
        }
        await db.users.insert_one(user_doc)
        # Record pending referral
        if payload.referral_code:
            inviter = await db.users.find_one({"referral_code": payload.referral_code})
            if inviter:
                await db.referrals.insert_one({
                    "id": new_id(),
                    "inviter_id": inviter["id"],
                    "invitee_id": user_doc["id"],
                    "invitee_name": payload.name,
                    "status": "pending",  # becomes 'rewarded' on first payment
                    "credit_amount": REFERRAL_CREDIT,
                    "created_at": now_utc(),
                })
    code = f"{random.randint(0, 999999):06d}"
    await db.otps.delete_many({"mobile": payload.mobile})
    await db.otps.insert_one({"mobile": payload.mobile, "code": code,
                              "expires_at": now_utc() + timedelta(minutes=OTP_EXP_MIN), "consumed": False})
    log.info(f"[DEV] OTP for {payload.mobile} = {code}")
    return {"message": "OTP sent", "dev_otp": code}


@api.post("/auth/login")
async def login(payload: LoginIn):

    user = await db.users.find_one({
        "mobile": payload.mobile
    })

    code = f"{random.randint(0, 999999):06d}"

    await db.otps.delete_many({
        "mobile": payload.mobile
    })

    await db.otps.insert_one({
        "mobile": payload.mobile,
        "code": code,
        "expires_at": now_utc() + timedelta(minutes=OTP_EXP_MIN),
        "consumed": False
    })

    log.info(
        f"[DEV] OTP for {payload.mobile} = {code}"
    )

    return {
        "message": "OTP sent",
        "dev_otp": code,
        "is_registered": user is not None
    }


@api.post("/auth/verify-otp", response_model=VerifyOtpOut)
async def verify_otp(payload: VerifyOtpIn):
    rec = await db.otps.find_one(
        {"mobile": payload.mobile, "consumed": False},
        {"_id": 0}
    )

    if not rec:
        raise HTTPException(400, "No OTP requested")

    exp = rec["expires_at"]

    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)

    if exp < now_utc():
        raise HTTPException(400, "OTP expired")

    if rec["code"] != payload.otp:
        raise HTTPException(400, "Invalid OTP")

    await db.otps.update_many(
        {"mobile": payload.mobile},
        {"$set": {"consumed": True}}
    )

    user = await db.users.find_one(
        {"mobile": payload.mobile},
        {"_id": 0}
    )

    # User does not exist -> Registration flow
    if not user:
        return VerifyOtpOut(
            is_registered=False,
            mobile=payload.mobile
        )

    # Existing user
    if not user.get("is_active"):
        await db.users.update_one(
            {"id": user["id"]},
            {"$set": {"is_active": True}}
        )
        user["is_active"] = True

    token = make_token(user["id"])

    return VerifyOtpOut(
        is_registered=True,
        token=TokenOut(
            access_token=token
        ),
        user=await user_to_out(user)
    )

@api.get("/auth/me", response_model=UserOut)
async def me(user=Depends(get_current_user)):
    return await user_to_out(user)


@api.post("/auth/seed-demo")
async def seed_demo(user=Depends(get_current_user)):
    if user.get("role") == "resident":
        await seed_user_invoices(user["id"])
    return {"ok": True}


@api.get("/auth/preferences")
async def get_preferences(user=Depends(get_current_user)):
    prefs = user.get("preferences") or {}
    # Merge with defaults for any missing keys (forward-compat)
    merged = {
        "privacy": {**DEFAULT_PREFS["privacy"], **(prefs.get("privacy") or {})},
        "notifications": {**DEFAULT_PREFS["notifications"], **(prefs.get("notifications") or {})},
    }
    return merged


@api.patch("/auth/preferences")
async def update_preferences(payload: PreferencesIn, user=Depends(get_current_user)):
    current = user.get("preferences") or {}
    privacy = {**DEFAULT_PREFS["privacy"], **(current.get("privacy") or {}), **(payload.privacy or {})}
    notifications = {**DEFAULT_PREFS["notifications"], **(current.get("notifications") or {}), **(payload.notifications or {})}
    new_prefs = {"privacy": privacy, "notifications": notifications}
    await db.users.update_one({"id": user["id"]}, {"$set": {"preferences": new_prefs}})
    return new_prefs

@api.get("/public/societies/search")
async def search_societies(q: str):

    return await db.tenants.find(
        {
            "status": "active",
            "name": {
                "$regex": q,
                "$options": "i"
            }
        },
        {
            "_id": 0,
            "id": 1,
            "name": 1,
            "city": 1
        }
    ).limit(20).to_list(20)
@api.get("/public/societies/{tenant_id}/towers")
async def get_towers(tenant_id: str):

    return await db.towers.find(
        {
            "tenant_id": tenant_id
        },
        {
            "_id": 0
        }
    ).sort("name", 1).to_list(100)
@api.get("/public/towers/{tower_id}/units")
async def get_units(tower_id: str):

    return await db.units.find(
        {
            "tower_id": tower_id,
            "occupancy_status": "available"
        },
        {
            "_id": 0
        }
    ).sort("unit_no", 1).to_list(1000)
@api.post("/public/register-request")
async def register_request(
    payload: RegistrationRequestIn
):

    tenant = await db.tenants.find_one(
        {
            "id": payload.tenant_id,
            "status": "active"
        }
    )

    if not tenant:
        raise HTTPException(
            404,
            "Society not found"
        )

    if tenant["invite_code"] != payload.invite_code:
        raise HTTPException(
            400,
            "Invalid invite code"
        )

    existing = await db.users.find_one(
        {
            "mobile": payload.mobile
        }
    )

    if existing:
        raise HTTPException(
            400,
            "Mobile already registered"
        )

    unit = await db.units.find_one(
        {
            "id": payload.unit_id,
            "tower_id": payload.tower_id
        }
    )

    if not unit:
        raise HTTPException(
            404,
            "Unit not found"
        )

    if unit["occupancy_status"] != "available":
        raise HTTPException(
            400,
            "Unit not available"
        )

    await db.units.update_one(
        {
            "id": payload.unit_id
        },
        {
            "$set": {
                "occupancy_status": "pending_approval"
            }
        }
    )

    await db.registration_requests.insert_one(
        {
            "id": new_id(),

            "tenant_id": payload.tenant_id,

            "tower_id": payload.tower_id,

            "unit_id": payload.unit_id,

            "name": payload.name,

            "mobile": payload.mobile,

            "email": payload.email,

            "invite_code": payload.invite_code,

            "status": "pending",

            "created_at": now_utc()
        }
    )

    return {
        "success": True,
        "message": "Request submitted"
    }
# ---- Resident Dashboard ----
@api.get("/dashboard")
async def dashboard(user=Depends(require_role("resident"))):
    pending_inv = await db.invoices.find_one({"user_id": user["id"], "status": "pending"}, {"_id": 0})
    open_comp = await db.complaints.count_documents({"user_id": user["id"], "status": {"$in": ["open", "in_progress"]}})
    today = now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
    visitors_today = await db.visitors.count_documents({"user_id": user["id"], "created_at": {"$gte": today}})
    pending_visitors = await db.visitors.count_documents({"user_id": user["id"], "status": "pending"})
    recent_notices = await db.notices.find({"tenant_id": user["tenant_id"]}, {"_id": 0}).sort("created_at", -1).limit(3).to_list(3)
    return {
        "pending_maintenance": pending_inv["amount"] if pending_inv else 0,
        "pending_invoice_id": pending_inv["id"] if pending_inv else None,
        "open_complaints": open_comp,
        "visitors_today": visitors_today,
        "pending_visitors": pending_visitors,
        "recent_notices": recent_notices,
    }


# ---- Resident: Visitors ----
@api.get("/visitors")
async def list_visitors(user=Depends(require_role("resident")), status_filter: Optional[str] = None):
    q = {"user_id": user["id"]}
    if status_filter:
        q["status"] = status_filter
    return await db.visitors.find(q, {"_id": 0}).sort("created_at", -1).to_list(100)


@api.post("/visitors")
async def create_visitor(payload: VisitorIn, user=Depends(require_role("resident"))):
    is_expected = payload.expected_at is not None
    doc = {
        "id": new_id(), "user_id": user["id"], "tenant_id": user["tenant_id"],
        "flat_no": user["flat_no"], "tower": user.get("tower", "A"),
        "resident_name": user["name"],
        "name": payload.name, "mobile": payload.mobile, "purpose": payload.purpose,
        "visitor_type": payload.visitor_type, "photo_base64": payload.photo_base64,
        "expected_at": payload.expected_at,
        "status": "expected" if is_expected else "pending",
        "created_at": now_utc(),
    }
    await db.visitors.insert_one(doc)
    doc.pop("_id", None)
    return doc
@api.post("/visitors/{vid}/action")
async def visitor_action(vid: str, payload: VisitorActionIn, user=Depends(require_role("resident"))):
    v = await db.visitors.find_one({"id": vid, "user_id": user["id"]}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Visitor not found")
    new_status = {"approve": "approved", "reject": "rejected"}.get(payload.action, v["status"])
    await db.visitors.update_one({"id": vid}, {"$set": {"status": new_status}})
    v["status"] = new_status
    return v


# ---- Resident: Complaints ----
@api.get("/complaints")
async def list_complaints(user=Depends(require_role("resident"))):
    return await db.complaints.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)


@api.post("/complaints")
async def create_complaint(payload: ComplaintIn, user=Depends(require_role("resident"))):
    count = await db.complaints.count_documents({}) + 1
    n = now_utc()
    doc = {
        "id": new_id(), "user_id": user["id"], "tenant_id": user["tenant_id"],
        "ticket_no": f"SH-{count:05d}", "resident_name": user["name"], "flat_no": user["flat_no"],
        "category": payload.category, "description": payload.description, "priority": payload.priority,
        "image_base64": payload.image_base64, "status": "open", "assigned_to": None,
        "timeline": [{"status": "open", "at": n.isoformat(), "note": "Complaint registered"}],
        "created_at": n, "updated_at": n,
    }
    await db.complaints.insert_one(doc)
    doc.pop("_id", None)
    return doc


# ---- Notices (shared read, admin create) ----
@api.get("/notices")
async def list_notices(user=Depends(get_current_user), category: Optional[str] = None):
    q = {"tenant_id": user["tenant_id"]}
    if category and category != "all":
        q["category"] = category
    docs = await db.notices.find(q, {"_id": 0}).sort("created_at", -1).to_list(100)
    reads = await db.notice_reads.find({"user_id": user["id"]}, {"_id": 0}).to_list(500)
    read_set = {r["notice_id"] for r in reads if r.get("read")}
    bm_set = {r["notice_id"] for r in reads if r.get("bookmarked")}
    for d in docs:
        d["read"] = d["id"] in read_set
        d["bookmarked"] = d["id"] in bm_set
    return docs


@api.post("/notices/{nid}/read")
async def mark_read(nid: str, user=Depends(get_current_user)):
    await db.notice_reads.update_one(
        {"user_id": user["id"], "notice_id": nid}, {"$set": {"read": True}}, upsert=True)
    return {"ok": True}


@api.post("/notices/{nid}/bookmark")
async def toggle_bm(nid: str, user=Depends(get_current_user)):
    existing = await db.notice_reads.find_one({"user_id": user["id"], "notice_id": nid})
    new_val = not (existing and existing.get("bookmarked"))
    await db.notice_reads.update_one(
        {"user_id": user["id"], "notice_id": nid}, {"$set": {"bookmarked": new_val}}, upsert=True)
    return {"bookmarked": new_val}


# ---- Resident: Invoices + Payment ----
@api.get("/invoices")
async def list_invoices(user=Depends(require_role("resident"))):
    return await db.invoices.find({"user_id": user["id"]}, {"_id": 0}).sort("due_date", -1).to_list(100)


@api.post("/invoices/pay")
async def pay_invoice(payload: PayIn, user=Depends(require_role("resident"))):
    inv = await db.invoices.find_one({"id": payload.invoice_id, "user_id": user["id"]}, {"_id": 0})
    if not inv:
        raise HTTPException(404, "Invoice not found")
    if inv["status"] == "paid":
        raise HTTPException(400, "Already paid")
    # apply referral credit at order creation (preview)
    credit = min(user.get("referral_credit", 0.0), inv["amount"])
    return {
        "order_id": f"order_mock_{new_id()[:12]}", "razorpay_key": "rzp_test_MOCK_KEY",
        "amount": inv["amount"], "credit_applied": credit, "net_amount": inv["amount"] - credit,
        "invoice_no": inv["invoice_no"],
    }


@api.post("/invoices/{iid}/confirm")
async def confirm_payment(iid: str, user=Depends(require_role("resident"))):
    inv = await db.invoices.find_one({"id": iid, "user_id": user["id"]}, {"_id": 0})
    if not inv:
        raise HTTPException(404, "Invoice not found")
    # apply referral credit
    credit = min(user.get("referral_credit", 0.0), inv["amount"])
    if credit > 0:
        await db.users.update_one({"id": user["id"]}, {"$inc": {"referral_credit": -credit}})
    await db.invoices.update_one({"id": iid}, {"$set": {"status": "paid", "paid_at": now_utc(), "credit_applied": credit}})
    # Reward inviter on first payment of referred user
    if user.get("referred_by_code"):
        ref = await db.referrals.find_one({"invitee_id": user["id"], "status": "pending"})
        if ref:
            inviter = await db.users.find_one({"referral_code": user["referred_by_code"]})
            if inviter:
                await db.users.update_one({"id": inviter["id"]}, {"$inc": {"referral_credit": REFERRAL_CREDIT}})
                await db.referrals.update_one({"id": ref["id"]}, {"$set": {"status": "rewarded", "rewarded_at": now_utc()}})
    return {"status": "paid", "credit_applied": credit}


# ---- Referrals (resident) ----
@api.get("/referrals")
async def my_referrals(user=Depends(require_role("resident"))):
    items = await db.referrals.find({"inviter_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    rewarded = sum(1 for r in items if r["status"] == "rewarded")
    pending = sum(1 for r in items if r["status"] == "pending")
    return {
        "code": user.get("referral_code"),
        "credit_balance": user.get("referral_credit", 0.0),
        "credit_per_referral": REFERRAL_CREDIT,
        "rewarded_count": rewarded,
        "pending_count": pending,
        "referrals": items,
    }

# ============================================================
# SUPER ADMIN ROUTES
# ============================================================
@api.post("/super-admin/tenant")
async def create_tenant(
    payload: TenantCreateIn,
    user=Depends(require_role("super_admin"))
):
    invite_code = gen_invite_code(
        payload.name
    )

    while await db.tenants.find_one(
        {
            "invite_code": invite_code
        }
    ):
        invite_code = gen_invite_code(
            payload.name
        )

    tenant = {
        "id": new_id(),
        "name": payload.name,
        "address": payload.address,
        "city": payload.city,
        "invite_code": invite_code,
        "status": "active",
        "created_at": now_utc()
    }

    await db.tenants.insert_one(
        tenant
    )

    return {
        "id": tenant["id"],
        "name": tenant["name"],
        "address": tenant["address"],
        "city": tenant["city"],
        "invite_code": tenant["invite_code"],
        "status": tenant["status"]
    }

@api.post("/super-admin/tower")
async def create_tower(
    payload: TowerCreateIn,
    user=Depends(require_role("super_admin"))
):

    tower = {
        "id": new_id(),
        "tenant_id": payload.tenant_id,
        "name": payload.name,
        "created_at": now_utc()
    }

    await db.towers.insert_one(tower)

    return {
        "id": tower["id"],
        "tenant_id": tower["tenant_id"],
        "name": tower["name"]
    }


@api.post("/super-admin/unit")
async def create_unit(
    payload: UnitCreateIn,
    user=Depends(require_role("super_admin"))
):

    unit = {
        "id": new_id(),
        "tenant_id": payload.tenant_id,
        "tower_id": payload.tower_id,
        "unit_no": payload.unit_no,

        "occupancy_status": "available",

        "owner_user_id": None,
        "current_resident_user_id": None,

        "created_at": now_utc()
    }

    await db.units.insert_one(unit)

    return {
    "id": unit["id"],
    "tenant_id": unit["tenant_id"],
    "tower_id": unit["tower_id"],
    "unit_no": unit["unit_no"],
    "occupancy_status": unit["occupancy_status"]
}

@api.get("/super-admin/tenants")
async def get_tenants(
    user=Depends(require_role("super_admin"))
):
    tenants = await db.tenants.find(
        {},
        {"_id": 0}
    ).sort(
        "created_at",
        -1
    ).to_list(None)

    return tenants

@api.post("/super-admin/society-admin")
async def create_society_admin(
    payload: CreateSocietyAdminIn,
    user=Depends(require_role("super_admin"))
):
    tenant = await db.tenants.find_one(
        {"id": payload.tenant_id}
    )

    if not tenant:
        raise HTTPException(
            404,
            "Society not found"
        )

    existing = await db.users.find_one({
        "mobile": payload.mobile
    })

    if existing:
        raise HTTPException(
            400,
            "Mobile already registered"
        )

    admin = {
        "id": new_id(),
        "tenant_id": payload.tenant_id,
        "mobile": payload.mobile,
        "name": payload.name,
        "email": payload.email,
        "role": "society_admin",
        "is_active": True,
        "created_at": now_utc()
    }

    await db.users.insert_one(admin)

    admin.pop("_id", None)

    return admin

@api.get(
    "/super-admin/tenant/{tenant_id}/admin"
)
async def get_society_admin(
    tenant_id: str,
    user=Depends(require_role("super_admin"))
):
    admin = await db.users.find_one(
        {
            "tenant_id": tenant_id,
            "role": "society_admin"
        },
        {"_id": 0}
    )

    if not admin:
        raise HTTPException(
            404,
            "Admin not found"
        )

    return admin

@api.get(
    "/super-admin/tenant/{tenant_id}/towers"
)
async def get_towers(
    tenant_id: str,
    user=Depends(require_role("super_admin"))
):
    towers = await db.towers.find(
        {
            "tenant_id": tenant_id
        },
        {"_id": 0}
    ).sort(
        "created_at",
        1
    ).to_list(None)

    return towers

@api.get(
    "/super-admin/tower/{tower_id}/units"
)
async def get_units(
    tower_id: str,
    user=Depends(require_role("super_admin"))
):
    units = await db.units.find(
        {
            "tower_id": tower_id
        },
        {"_id": 0}
    ).sort(
        "unit_no",
        1
    ).to_list(None)

    return units

@api.get("/super-admin/dashboard")
async def super_admin_dashboard(
    user=Depends(require_role("super_admin"))
):
    societies = await db.tenants.count_documents({})

    residents = await db.users.count_documents(
        {"role": "resident"}
    )

    pending_requests = await db.registration_requests.count_documents(
        {"status": "pending"}
    )

    complaints = await db.complaints.count_documents(
        {}
    )

    return {
        "societies": societies,
        "residents": residents,
        "pending_requests": pending_requests,
        "complaints": complaints,
    }
# ============================================================
# ADMIN ROUTES
# ============================================================
@api.get("/admin/registration-requests")
async def pending_registration_requests(
    user=Depends(require_role("society_admin"))
):

    return await db.registration_requests.find(
        {
            "tenant_id": user["tenant_id"],
            "status": "pending"
        },
        {
            "_id": 0
        }
    ).to_list(1000)


@api.post("/admin/registration-requests/{rid}/approve")
async def approve_request(
    rid: str,
    user=Depends(require_role("society_admin"))
):

    req = await db.registration_requests.find_one(
        {
            "id": rid,
            "status": "pending"
        }
    )

    if not req:
        raise HTTPException(
            404,
            "Request not found"
        )

    resident_id = new_id()
    tower = await db.towers.find_one(
        {"id": req["tower_id"]},
        {"_id": 0}
    )

    unit = await db.units.find_one(
        {"id": req["unit_id"]},
        {"_id": 0}
    )
    await db.users.insert_one(
    {
        "id": resident_id,
        "tenant_id":
            req["tenant_id"],
        "tower_id":
            req["tower_id"],
        "tower":
            tower["name"],
        "unit_id":
            req["unit_id"],
        "flat_no":
            unit['unit_no'],
        "name":
            req["name"],
        "mobile":
            req["mobile"],
        "email":
            req["email"],
        "role":
            "resident",
        "is_active":
            True,
        "created_at":
            now_utc()
    }
)

    await db.units.update_one(
        {
            "id": req["unit_id"]
        },
        {
            "$set": {
                "occupancy_status": "occupied",
                "current_resident_user_id": resident_id
            }
        }
    )

    await db.registration_requests.update_one(
        {
            "id": rid
        },
        {
            "$set": {
                "status": "approved",
                "approved_at": now_utc()
            }
        }
    )

    return {
        "success": True
    }


@api.post("/admin/registration-requests/{rid}/reject")
async def reject_request(
    rid: str,
    payload: RegistrationRequestActionIn,
    user=Depends(require_role("society_admin"))
):

    req = await db.registration_requests.find_one(
        {
            "id": rid,
            "status": "pending"
        }
    )

    if not req:
        raise HTTPException(
            404,
            "Request not found"
        )

    await db.units.update_one(
        {
            "id": req["unit_id"]
        },
        {
            "$set": {
                "occupancy_status": "available"
            }
        }
    )

    await db.registration_requests.update_one(
        {
            "id": rid
        },
        {
            "$set": {
                "status": "rejected",
                "reason": payload.reason,
                "rejected_at": now_utc()
            }
        }
    )

    return {
        "success": True
    }
@api.post(
    "/super-admin/units/bulk"
)
async def bulk_create_units(
    payload: BulkUnitIn,
    user=Depends(require_role("super_admin"))
):
    if payload.start > payload.end:
        raise HTTPException(
            400,
            "Invalid range"
        )

    tower = await db.towers.find_one(
        {
            "id": payload.tower_id
        }
    )

    if not tower:
        raise HTTPException(
            404,
            "Tower not found"
        )

    units = []

    for i in range(
        payload.start,
        payload.end + 1
    ):
        unit_no = f"{payload.prefix}-{i}"

        exists = await db.units.find_one(
            {
                "tower_id": payload.tower_id,
                "unit_no": unit_no
            }
        )

        if exists:
            continue

        units.append({
            "id": new_id(),
            "tenant_id":
                payload.tenant_id,
            "tower_id":
                payload.tower_id,
            "unit_no":
                unit_no,
            "occupancy_status":
                "available",
            "created_at":
                now_utc()
        })

    if units:
        await db.units.insert_many(
            units
        )

    return {
        "count": len(units)
    }

@api.get(
    "/super-admin/dashboard"
)
async def super_admin_dashboard(
    user=Depends(require_role("super_admin"))
):
    societies = await db.tenants.count_documents({})
    residents = await db.users.count_documents(
        {
            "role": "resident"
        }
    )

    pending_requests = await db.registration_requests.count_documents(
        {
            "status": "pending"
        }
    )

    complaints = await db.complaints.count_documents(
        {}
    )

    return {
        "societies": societies,
        "residents": residents,
        "pending_requests":
            pending_requests,
        "complaints":
            complaints
    }
@api.delete(
    "/super-admin/unit/{unit_id}"
)
async def delete_unit(
    unit_id: str,
    user=Depends(require_role("super_admin"))
):
    await db.units.delete_one(
        {
            "id": unit_id
        }
    )

    return {
        "message":
            "Unit deleted"
    }
@api.delete(
    "/super-admin/tower/{tower_id}"
)
async def delete_tower(
    tower_id: str,
    user=Depends(require_role("super_admin"))
):
    await db.units.delete_many(
        {
            "tower_id":
                tower_id
        }
    )

    await db.towers.delete_one(
        {
            "id": tower_id
        }
    )

    return {
        "message":
            "Tower deleted"
    }
@api.delete(
    "/super-admin/tenant/{tenant_id}"
)
async def delete_tenant(
    tenant_id: str,
    user=Depends(require_role("super_admin"))
):
    await db.units.delete_many(
        {
            "tenant_id":
                tenant_id
        }
    )

    await db.towers.delete_many(
        {
            "tenant_id":
                tenant_id
        }
    )

    await db.users.delete_many(
        {
            "tenant_id":
                tenant_id
        }
    )

    await db.registration_requests.delete_many(
        {
            "tenant_id":
                tenant_id
        }
    )

    await db.tenants.delete_one(
        {
            "id": tenant_id
        }
    )

    return {
        "message":
            "Society deleted"
    }

@api.get("/admin/dashboard")
async def admin_dashboard(user=Depends(require_role("society_admin"))):
    sid = user["tenant_id"]
    total_residents = await db.users.count_documents({"tenant_id": sid, "role": "resident"})
    total_complaints = await db.complaints.count_documents({"tenant_id": sid})
    open_complaints = await db.complaints.count_documents({"tenant_id": sid, "status": {"$in": ["open", "in_progress"]}})
    today = now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
    visitors_today = await db.visitors.count_documents({"tenant_id": sid, "created_at": {"$gte": today}})
    paid = await db.invoices.aggregate([
        {
    "$match": {
        "tenant_id": sid,
        "status": "paid"
    }
},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    pending = await db.invoices.aggregate([
        {
    "$match": {
        "tenant_id": sid,
        "status": "pending"
    }
},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    recent_complaints = await db.complaints.find({"tenant_id": sid}, {"_id": 0}).sort("created_at", -1).limit(5).to_list(5)
    return {
        "total_residents": total_residents,
        "open_complaints": open_complaints,
        "total_complaints": total_complaints,
        "visitors_today": visitors_today,
        "monthly_collection": paid[0]["total"] if paid else 0,
        "pending_dues": pending[0]["total"] if pending else 0,
        "recent_complaints": recent_complaints,
    }


@api.get("/admin/residents")
async def admin_list_residents(user=Depends(require_role("society_admin")), search: Optional[str] = None):
    q = {"tenant_id": user["tenant_id"], "role": "resident"}
    if search:
        q["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"flat_no": {"$regex": search, "$options": "i"}},
            {"mobile": {"$regex": search}},
        ]
    items = await db.users.find(q, {"_id": 0, "is_active": 0}).sort("flat_no", 1).to_list(500)
    return items

@api.post("/admin/residents")
async def admin_add_resident(
    payload: ResidentIn,
    user=Depends(require_role("society_admin"))
):
    existing = await db.users.find_one(
        {"mobile": payload.mobile}
    )

    if existing:
        raise HTTPException(
            400,
            "User with this mobile already exists"
        )

    tower = await db.towers.find_one(
        {
            "id": payload.tower_id,
            "tenant_id": user["tenant_id"]
        }
    )

    if not tower:
        raise HTTPException(
            404,
            "Tower not found"
        )

    unit = await db.units.find_one(
        {
            "id": payload.unit_id,
            "tower_id": payload.tower_id
        }
    )

    if not unit:
        raise HTTPException(
            404,
            "Unit not found"
        )

    if unit["occupancy_status"] != "available":
        raise HTTPException(
            400,
            "Unit already occupied"
        )

    resident_id = new_id()

    ref_code = gen_ref_code(
        payload.name
    )

    while await db.users.find_one(
        {
            "referral_code":
                ref_code
        }
    ):
        ref_code = gen_ref_code(
            payload.name
        )

    doc = {
        "id": resident_id,

        "mobile": payload.mobile,
        "name": payload.name,
        "email": payload.email,

        "tenant_id": user["tenant_id"],

        "tower_id": payload.tower_id,
        "tower": tower["name"],

        "unit_id": payload.unit_id,
        "flat_no":
            unit['unit_no'],

        "role": "resident",
        "is_active": True,

        "avatar": None,

        "referral_code": ref_code,
        "referred_by_code": None,
        "referral_credit": 0.0,

        "created_at": now_utc(),
    }

    await db.users.insert_one(doc)

    await db.units.update_one(
        {
            "id": payload.unit_id
        },
        {
            "$set": {
                "occupancy_status":
                    "occupied",
                "current_resident_user_id":
                    resident_id
            }
        }
    )

    doc.pop("_id", None)

    return doc


@api.patch("/admin/residents/{rid}")
async def admin_update_resident(rid: str, payload: ResidentUpdateIn, user=Depends(require_role("society_admin"))):
    upd = {k: v for k, v in payload.dict().items() if v is not None}
    res = await db.users.update_one({"id": rid, "tenant_id": user["tenant_id"], "role": "resident"}, {"$set": upd})
    if res.matched_count == 0:
        raise HTTPException(404, "Resident not found")
    return {"ok": True}


@api.delete(
    "/admin/residents/{rid}"
)
async def admin_delete_resident(
    rid: str,
    user=Depends(
        require_role(
            "society_admin"
        )
    )
):
    resident = await db.users.find_one(
        {
            "id": rid,
            "tenant_id":
                user["tenant_id"],
            "role":
                "resident"
        }
    )

    if not resident:
        raise HTTPException(
            404,
            "Resident not found"
        )

    if resident.get("unit_id"):
        await db.units.update_one(
            {
                "id":
                    resident["unit_id"]
            },
            {
                "$set":
                {
                    "occupancy_status":
                        "available",
                    "current_resident_user_id":
                        None
                }
            }
        )

    await db.users.delete_one(
        {
            "id": rid
        }
    )

    return {
        "ok": True
    }

@api.get("/admin/complaints")
async def admin_list_complaints(user=Depends(require_role("society_admin"))):
    return await db.complaints.find({"tenant_id": user["tenant_id"]}, {"_id": 0}).sort("created_at", -1).to_list(500)


@api.patch("/admin/complaints/{cid}")
async def admin_update_complaint(cid: str, payload: ComplaintUpdateIn, user=Depends(require_role("society_admin"))):
    c = await db.complaints.find_one({"id": cid, "tenant_id": user["tenant_id"]}, {"_id": 0})
    if not c:
        raise HTTPException(404, "Complaint not found")
    upd = {}
    timeline = c.get("timeline", [])
    if payload.status and payload.status != c["status"]:
        upd["status"] = payload.status
        timeline.append({"status": payload.status, "at": now_utc().isoformat(),
                         "note": payload.note or f"Status changed to {payload.status} by {user['name']}"})
    if payload.assigned_to:
        upd["assigned_to"] = payload.assigned_to
        timeline.append({"status": c["status"], "at": now_utc().isoformat(),
                         "note": f"Assigned to {payload.assigned_to}"})
    if upd:
        upd["timeline"] = timeline
        upd["updated_at"] = now_utc()
        await db.complaints.update_one({"id": cid}, {"$set": upd})
    fresh = await db.complaints.find_one({"id": cid}, {"_id": 0})
    # Notify complaint owner on status change
    if payload.status and payload.status != c["status"]:
        owner = await db.users.find_one({"id": c["user_id"]}, {"_id": 0})
        if owner:
            await push_to_user(
                owner,
                pref_key="complaint_updates_push",
                title=f"Complaint {c['ticket_no']} updated",
                message=f"Status changed to {payload.status.replace('_', ' ').title()}",
                action_url="/(tabs)/complaints",
                idempotency_key=f"complaint-{cid}-{payload.status}",
            )
    return fresh


@api.post("/admin/notices")
async def admin_create_notice(payload: NoticeIn, user=Depends(require_role("society_admin"))):
    doc = {
        "id": new_id(), "tenant_id": user["tenant_id"],
        "title": payload.title, "body": payload.body, "category": payload.category,
        "created_at": now_utc(), "created_by": user["name"],
    }
    await db.notices.insert_one(doc)
    doc.pop("_id", None)
    # Push to all residents in society — emergencies are urgent
    residents = await db.users.find(
        {"tenant_id": user["tenant_id"], "role": "resident"},
        {"_id": 0},
    ).to_list(2000)
    await push_to_users(
        residents,
        pref_key="new_notices_push",
        title=f"[{payload.category.upper()}] {payload.title}",
        message=payload.body[:120],
        urgent=(payload.category == "emergency"),
        action_url="/(tabs)/notices",
        idempotency_key=f"notice-{doc['id']}",
    )
    return doc


@api.delete("/admin/notices/{nid}")
async def admin_delete_notice(nid: str, user=Depends(require_role("society_admin"))):
    await db.notices.delete_one({"id": nid, "tenant_id": user["tenant_id"]})
    return {"ok": True}
@api.get("/admin/towers")
async def admin_towers(
    user=Depends(
        require_role("society_admin")
    )
):
    return await db.towers.find(
        {
            "tenant_id":
                user["tenant_id"]
        },
        {
            "_id": 0
        }
    ).sort(
        "name",
        1
    ).to_list(None)

@api.get(
    "/admin/towers/{tower_id}/units"
)
async def admin_units(
    tower_id: str,
    user=Depends(
        require_role(
            "society_admin"
        )
    )
):
    return await db.units.find(
        {
            "tower_id":
                tower_id,

            "occupancy_status":
                "available"
        },
        {
            "_id": 0
        }
    ).sort(
        "unit_no",
        1
    ).to_list(None)

# ============================================================
# GUARD ROUTES
# ============================================================
@api.get("/guard/dashboard")
async def guard_dashboard(user=Depends(require_role("security_guard"))):
    sid = user["tenant_id"]
    today = now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
    visitors_today = await db.visitors.count_documents({"tenant_id": sid, "created_at": {"$gte": today}})
    expected = await db.visitors.count_documents({"tenant_id": sid, "status": "expected"})
    pending_approval = await db.visitors.count_documents({"tenant_id": sid, "status": "pending"})
    checked_in = await db.visitors.count_documents({"tenant_id": sid, "status": "checked_in"})
    return {
        "visitors_today": visitors_today,
        "expected": expected,
        "pending_approval": pending_approval,
        "checked_in": checked_in,
    }


@api.get("/guard/visitors")
async def guard_visitors(user=Depends(require_role("security_guard")), status_filter: Optional[str] = None):
    q = {"tenant_id": user["tenant_id"]}
    if status_filter and status_filter != "all":
        q["status"] = status_filter
    return await db.visitors.find(q, {"_id": 0}).sort("created_at", -1).limit(200).to_list(200)


@api.post("/guard/visitors")
async def guard_add_visitor(payload: VisitorIn, user=Depends(require_role("security_guard"))):
    if not payload.flat_no:
        raise HTTPException(400, "flat_no required")
    resident = await db.users.find_one({"tenant_id": user["tenant_id"], "flat_no": payload.flat_no, "role": "resident"})
    if not resident:
        raise HTTPException(404, f"No resident at flat {payload.flat_no}")
    doc = {
        "id": new_id(), "user_id": resident["id"], "tenant_id": user["tenant_id"],
        "flat_no": payload.flat_no, "tower": resident.get("tower", "A"),
        "resident_name": resident["name"],
        "name": payload.name, "mobile": payload.mobile, "purpose": payload.purpose,
        "visitor_type": payload.visitor_type, "photo_base64": payload.photo_base64,
        "status": "pending",  # waiting for resident approval
        "created_at": now_utc(), "logged_by_guard": user["name"],
    }
    await db.visitors.insert_one(doc)
    doc.pop("_id", None)
    # Push to the resident — URGENT (bypasses quiet hours since someone is at the gate)
    await push_to_user(
        resident,
        pref_key="visitor_approvals_push",
        title=f"Visitor at your door",
        message=f"{payload.name} ({payload.visitor_type}) is here to see you. Tap to approve.",
        urgent=True,
        action_url="/(tabs)/visitors",
        idempotency_key=f"visitor-{doc['id']}",
    )
    return doc


@api.post("/guard/visitors/{vid}/checkin")
async def guard_checkin(vid: str, user=Depends(require_role("security_guard"))):
    v = await db.visitors.find_one({"id": vid, "tenant_id": user["tenant_id"]}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Visitor not found")
    if v["status"] not in ("approved", "expected"):
        raise HTTPException(400, f"Cannot check-in visitor with status {v['status']}")
    await db.visitors.update_one({"id": vid}, {"$set": {"status": "checked_in", "checked_in_at": now_utc()}})
    return {"ok": True}


@api.post("/guard/visitors/{vid}/checkout")
async def guard_checkout(vid: str, user=Depends(require_role("security_guard"))):
    await db.visitors.update_one(
        {"id": vid, "tenant_id": user["tenant_id"]},
        {"$set": {"status": "checked_out", "checked_out_at": now_utc()}})
    return {"ok": True}


# ============================================================
# Seeding
# ============================================================
async def seed_user_invoices(user_id: str):
    if await db.invoices.count_documents({"user_id": user_id}) > 0:
        return
    months = [
        ("Nov 2025", "pending", now_utc() + timedelta(days=5)),
        ("Oct 2025", "paid", now_utc() - timedelta(days=25)),
        ("Sep 2025", "paid", now_utc() - timedelta(days=55)),
    ]
    for i, (period, st, due) in enumerate(months):
        await db.invoices.insert_one({
            "id": new_id(), "user_id": user_id, "invoice_no": f"INV-{1000 + random.randint(100, 999)}",
            "period": period, "amount": 3500.0, "due_date": due, "status": st,
            "paid_at": (due - timedelta(days=2)) if st == "paid" else None,
            "created_at": now_utc() - timedelta(days=30 * i),
        })


async def seed():
    existing = await db.users.find_one(
        {
            "mobile": "9999999999",
            "role": "super_admin"
        }
    )

    if existing:
        return

    super_admin = {
        "id": new_id(),
        "mobile": "9999999999",
        "name": "SocioHub Admin",
        "email": "admin@sociohub.com",
        "role": "super_admin",
        "is_active": True,
        "created_at": now_utc()
    }

    await db.users.insert_one(
        super_admin
    )

    log.info(
        "Super Admin seeded successfully"
    )
@app.on_event("startup")
async def startup():
    await seed()


app.include_router(api)
app.include_router(push_router)

app.add_middleware(
    CORSMiddleware, allow_credentials=True, allow_origins=["*"],
    allow_methods=["*"], allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown():
    client.close()
