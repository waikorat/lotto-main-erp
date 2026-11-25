"""
common.py — โมดูลกลางที่ "ระบบหลัก" และ "ระบบตัวแทน" ต้อง import ใช้ร่วมกัน

หลักการ: ทุกอย่างที่เกี่ยวกับโครงสร้างฐานข้อมูล / การดึงเรต / เลขอั้น / เลขที่บิล /
การคำนวณเงินรางวัล อยู่ที่ไฟล์นี้ที่เดียว เพื่อไม่ให้สองระบบตีความข้อมูลต่างกันอีก

ต้องตั้ง environment variable:
  DB_URI          (บังคับ)  เช่น postgresql://user:pass@host:6543/postgres
  SECRET_KEY      (แนะนำ)   ใช้เซ็นคุกกี้ session — ถ้าไม่ตั้ง จะสุ่มใหม่ทุกครั้งที่รัน (ล็อกอินหลุดเมื่อรีสตาร์ท)
  HASH_PASSWORDS  (ไม่บังคับ) "1" = เก็บรหัสผ่านแบบแฮชเมื่อสร้าง/เปลี่ยนรหัส
                    *** เปิดได้ต่อเมื่อระบบหลักอัปเดตให้ใช้ verify_password() แล้วเท่านั้น ***
  ADMIN_USERNAME / ADMIN_PASSWORD (ไม่บังคับ) สร้างแอดมินเริ่มต้นเมื่อตาราง Users ว่าง
"""
import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import urllib.error
import urllib.request
from urllib.parse import quote

import psycopg2
from jinja2 import Template as _Jinja

# ============================================================ การเชื่อมต่อ DB

DB_URI = os.environ.get("DB_URI")
if not DB_URI:
    raise RuntimeError("ต้องตั้งค่า environment variable DB_URI (ห้ามฝังรหัสผ่านฐานข้อมูลไว้ในโค้ด)")


@contextmanager
def db():
    """with db() as conn: ...  -> commit เมื่อสำเร็จ, rollback เมื่อเกิด exception, ปิดการเชื่อมต่อเสมอ"""
    conn = psycopg2.connect(DB_URI)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_thai_time():
    """เวลาไทย (UTC+7) แบบ naive datetime"""
    return datetime.now(timezone(timedelta(hours=7))).replace(tzinfo=None)


def like_escape(s):
    return str(s).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ============================================================ บทบาท / สายงาน

ROLE_LEVEL = {"Admin": 0, "Master Agent": 1, "Agent": 2, "Member": 3}
CREATABLE_ROLES = {
    "Admin": ["Master Agent", "Agent", "Member"],
    "Master Agent": ["Agent", "Member"],
    "Agent": ["Member"],
    "Member": [],
}
MANAGER_ROLES = ("Admin", "Master Agent", "Agent")


def norm_role(role):
    r = (role or "").strip().lower()
    for k in ROLE_LEVEL:
        if k.lower() == r:
            return k
    return "Member"


def get_user(c, username):
    """คืน dict ของผู้ใช้ หรือ None  (ชื่อสายงานใช้คอลัมน์ parent_user เป็นมาตรฐาน)"""
    if not username:
        return None
    c.execute("SELECT id, username, role, parent_user FROM Users WHERE username=%s", (username,))
    r = c.fetchone()
    if not r:
        return None
    return {"id": r[0], "username": r[1], "role": norm_role(r[2]), "parent_user": r[3]}


def _is_root_admin(c, me):
    c.execute("SELECT id FROM Users WHERE LOWER(role)='admin' ORDER BY id LIMIT 1")
    r = c.fetchone()
    return bool(r) and r[0] == me["id"]


def direct_children(c, me):
    """ผู้ใช้ที่ me เป็น upline โดยตรง -> [(id, username, role)]
    บัญชีเก่าที่ไม่มี upline จริง (parent_user ว่าง/เป็นขีด "-"/ชื่อที่ไม่มีอยู่ในระบบ และไม่ใช่แอดมิน) ถือเป็นสายตรงของแอดมินคนแรก"""
    c.execute("SELECT id, username, role FROM Users WHERE id<>%s AND (LOWER(parent_user)=LOWER(%s) OR "
              "(%s AND NOT EXISTS (SELECT 1 FROM Users pp WHERE LOWER(pp.username) = LOWER(Users.parent_user)) AND LOWER(role)<>'admin')) ORDER BY id DESC",
              (me["id"], me["username"], _is_root_admin(c, me)))
    return c.fetchall()


def is_direct_child(c, me, user_id):
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return False
    return any(r[0] == user_id for r in direct_children(c, me))


def get_subtree(c, username):
    """username ของตัวเอง + ลูกข่ายทุกชั้น (กัน loop ด้วย UNION)"""
    c.execute(
        """WITH RECURSIVE t AS (
               SELECT username FROM Users WHERE username=%s
               UNION
               SELECT u.username FROM Users u JOIN t ON (
                   u.parent_user = t.username
                   OR (t.username = (SELECT username FROM Users WHERE LOWER(role)='admin' ORDER BY id LIMIT 1)
                       AND NOT EXISTS (SELECT 1 FROM Users pp WHERE LOWER(pp.username) = LOWER(u.parent_user)) AND LOWER(u.role) <> 'admin'))
           ) SELECT username FROM t""",
        (username,),
    )
    names = [r[0] for r in c.fetchall()]
    return names or [username]


# ============================================================ รหัสผ่าน / session

HASH_ENABLED = os.environ.get("HASH_PASSWORDS", "0") == "1"


def hash_password(pw):
    salt = secrets.token_hex(8)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
    return f"pbkdf2${salt}${dk}"


def verify_password(stored, given):
    """รองรับทั้งรหัสแบบแฮช (pbkdf2$...) และรหัสเดิมแบบ plaintext"""
    stored = stored or ""
    if stored.startswith("pbkdf2$"):
        try:
            _, salt, dk = stored.split("$")
        except ValueError:
            return False
        calc = hashlib.pbkdf2_hmac("sha256", given.encode(), salt.encode(), 200_000).hex()
        return hmac.compare_digest(dk, calc)
    return hmac.compare_digest(stored.encode(), given.encode())


def store_password(pw):
    return hash_password(pw) if HASH_ENABLED else pw


SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
if not os.environ.get("SECRET_KEY"):
    print("WARNING: ไม่ได้ตั้ง SECRET_KEY — session จะหมดอายุทุกครั้งที่รีสตาร์ท / รันหลาย worker ไม่ได้")
SESSION_COOKIE = "lotto_session"
SESSION_TTL = 12 * 3600


def _sign(data):
    return hmac.new(SECRET_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()


def make_session(username):
    payload = f"{username}|{int(time.time()) + SESSION_TTL}"
    b = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")   # ไม่ใส่ "=" ท้ายค่า เพราะทำให้เบราว์เซอร์/เซิร์ฟเวอร์ครอบคุกกี้ด้วยเครื่องหมายคำพูด
    return f"{b}.{_sign(b)}"


def read_session(value):
    """คืน username ถ้า cookie ถูกต้องและยังไม่หมดอายุ"""
    value = (value or "").strip().strip('"')
    if not value or "." not in value:
        return None
    b, sig = value.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(b)):
        return None
    try:
        username, exp = base64.urlsafe_b64decode((b + "=" * (-len(b) % 4)).encode()).decode().rsplit("|", 1)
        if int(exp) < time.time():
            return None
        return username
    except Exception:
        return None


def get_session_user(c, cookie_value):
    uname = read_session(cookie_value)
    return get_user(c, uname) if uname else None


# ============================================================ เรต / ส่วนลด

RATE_KEYS = ["pay_3d", "pay_3tod", "pay_2d", "pay_run_top", "pay_run_bot",
             "disc_3d", "disc_2d", "disc_run", "disc_total"]
RATE_DEFAULTS = dict(pay_3d=500.0, pay_3tod=100.0, pay_2d=70.0, pay_run_top=3.2, pay_run_bot=4.2,
                     disc_3d=0.0, disc_2d=0.0, disc_run=0.0, disc_total=0.0)


def clean_rates(raw):
    """ตรวจและจำกัดช่วงค่าเรต: จ่าย 0..1,000,000 / ส่วนลด 0..100"""
    out = {}
    for k in RATE_KEYS:
        try:
            v = float(raw.get(k, RATE_DEFAULTS[k]))
        except (TypeError, ValueError):
            v = RATE_DEFAULTS[k]
        if not math.isfinite(v):
            v = RATE_DEFAULTS[k]
        hi = 100.0 if k.startswith("disc_") else 1_000_000.0
        out[k] = round(min(max(v, 0.0), hi), 2)
    return out


def parse_target(customer_id):
    """'5' -> ('Customer', 5) ; 'user_5' -> ('User', 5)  (raise ValueError ถ้าผิดรูปแบบ)"""
    s = str(customer_id).strip()
    if s.startswith("user_"):
        return "User", int(s[5:])
    return "Customer", int(s)


def target_key(t_type, t_id):
    return f"user_{t_id}" if t_type == "User" else str(t_id)


def get_rates(c, customer_id, lotto_name):
    """
    ดึงเรตจุดเดียวสำหรับทุกระบบ
    ลำดับ: เรตแยกหวย (CustomerLottoRates.target_id) -> เรตพื้นฐานของ Users/Customers
    คืน (dict, source) โดย source = 'lotto' | 'default' หรือ (None, None) ถ้าไม่พบผู้ใช้/ลูกค้า
    ส่วนลด 0 ใช้ค่า 0 จริง ส่วนอัตราจ่ายที่เป็น 0/ว่าง ใช้ค่าเริ่มต้น
    """
    cols = ", ".join(RATE_KEYS)
    c.execute(
        f"SELECT {cols} FROM CustomerLottoRates WHERE target_id=%s AND lotto_name=%s ORDER BY id DESC LIMIT 1",
        (str(customer_id), lotto_name),
    )
    row, source = c.fetchone(), "lotto"
    if not row:
        t_type, t_id = parse_target(customer_id)
        table = "Users" if t_type == "User" else "Customers"
        c.execute(f"SELECT {cols} FROM {table} WHERE id=%s", (t_id,))
        row, source = c.fetchone(), "default"
    if not row:
        return None, None
    out = {}
    for k, v in zip(RATE_KEYS, row):
        if v is None or (k.startswith("pay_") and float(v) <= 0):
            out[k] = RATE_DEFAULTS[k]      # อัตราจ่าย 0 ไม่มีความหมาย (ข้อมูลเก่าเก็บ 0 แทนค่าว่าง) -> ใช้ค่าเริ่มต้น
        else:
            out[k] = float(v)              # ส่วนลด 0 = ไม่มีส่วนลด ใช้ค่า 0 จริง
    return out, source


def disc_pct(r, kind):
    """kind = '3d' | '2d' | 'run' : ส่วนลดเฉพาะประเภท ถ้าเป็น 0 ใช้ส่วนลดรวม"""
    v = r.get(f"disc_{kind}", 0.0)
    return v if v > 0 else r.get("disc_total", 0.0)


# ============================================================ สิทธิ์กำหนดเรต/ส่วนลด (เฉพาะ upline และไม่เกินเรตของตัวเอง)

RATE_LABELS = {"pay_3d": "จ่าย 3ตัวตรง", "pay_3tod": "จ่าย 3ตัวโต๊ด", "pay_2d": "จ่าย 2ตัว",
               "pay_run_top": "จ่ายวิ่งบน", "pay_run_bot": "จ่ายวิ่งล่าง",
               "disc_3d": "ส่วนลด 3ตัว", "disc_2d": "ส่วนลด 2ตัว", "disc_run": "ส่วนลดวิ่ง"}


def can_set_rates_for(c, me, t_type, t_id):
    """ตั้งเรตให้ได้เฉพาะ: ลูกค้าที่ตัวเองเป็นเจ้าของ และผู้ใช้ที่ตัวเองเป็น upline โดยตรง (ตั้งให้ตัวเองไม่ได้ — ทุกบทบาทรวมแอดมิน)"""
    try:
        t_id = int(t_id)
    except (TypeError, ValueError):
        return False
    if t_type == "Customer":
        c.execute("SELECT 1 FROM Customers WHERE id=%s AND LOWER(owner_username)=LOWER(%s)", (t_id, me["username"]))
    elif t_type == "User":
        return t_id != me["id"] and is_direct_child(c, me, t_id)
    else:
        return False
    return bool(c.fetchone())


def get_rate_targets(c, me):
    """รายชื่อที่ตั้งเรตให้ได้ (ไม่รวมตัวเอง): ลูกค้าของตัวเอง + ผู้ใช้ที่ตัวเองเป็น upline โดยตรง"""
    out = []
    c.execute("SELECT id, name FROM Customers WHERE LOWER(owner_username)=LOWER(%s) ORDER BY id DESC", (me["username"],))
    for r in c.fetchall():
        out.append({"key": str(r[0]), "kind": "Customer", "id": r[0], "label": f"ลูกค้า: {r[1]}"})
    for r in direct_children(c, me):
        out.append({"key": f"user_{r[0]}", "kind": "User", "id": r[0], "label": f"สายงาน: {r[1]}"})
    return out


def check_rates_within(c, me, v, lotto_name=None):
    """ตรวจว่าเรตที่จะตั้ง (dict v จาก clean_rates) ไม่เกินเรตที่ me ได้รับ
    lotto_name=None -> เทียบกับเรตพื้นฐานของ me ; ระบุชื่อหวย -> เทียบกับเรตของ me ในหวยนั้น (ถ้าไม่มีเรตแยกใช้เรตพื้นฐาน)
    แอดมินเป็นต้นสาย ไม่จำกัดเพดาน  คืน None ถ้าผ่าน หรือข้อความผิดพลาด"""
    if me["role"] == "Admin":
        return None
    cap, _src = get_rates(c, f"user_{me['id']}", lotto_name or "")
    if not cap:
        return "ไม่พบเรตของบัญชีคุณ ไม่สามารถกำหนดเรตให้ผู้อื่นได้ (ให้ upline ตั้งเรตให้คุณก่อน)"
    errs = []
    for k in ("pay_3d", "pay_3tod", "pay_2d", "pay_run_top", "pay_run_bot"):
        if v[k] > cap[k] + 1e-9:
            errs.append(f"{RATE_LABELS[k]} {v[k]:g} เกินเรตของคุณ ({cap[k]:g})")
    for kind, k in (("3d", "disc_3d"), ("2d", "disc_2d"), ("run", "disc_run")):
        mine, want = disc_pct(cap, kind), disc_pct(v, kind)
        if want > mine + 1e-9:
            errs.append(f"{RATE_LABELS[k]} {want:g}% เกินส่วนลดของคุณ ({mine:g}%)")
    return "เกินเรตที่คุณได้รับ: " + " · ".join(errs) if errs else None


# ชนิดการเล่นตามจำนวนหลัก: (ชื่อประเภท, คีย์เรตจ่าย, ชนิดส่วนลด)  [ช่อง "บน", ช่อง "ล่าง"]
PLAYS = {
    3: (("3ตัวตรง", "pay_3d", "3d"), ("3ตัวโต๊ด", "pay_3tod", "3d")),
    2: (("2ตัวบน", "pay_2d", "2d"), ("2ตัวล่าง", "pay_2d", "2d")),
    1: (("วิ่งบน", "pay_run_top", "run"), ("วิ่งล่าง", "pay_run_bot", "run")),
}


def get_targets(c, me, include_self=True):
    """รายชื่อ 'ผู้ซื้อ' ที่ผู้ใช้คนนี้เข้าถึงได้ (ใช้ทั้งหน้าโพยและหน้าตั้งเรต)"""
    out = []
    if include_self:
        out.append({"key": f"user_{me['id']}", "kind": "User", "id": me["id"],
                    "label": f"user: {me['username']} (บัญชีตัวเอง)"})
    # ทุกบทบาท (รวมแอดมิน): เฉพาะลูกค้าที่ตัวเองสร้าง และผู้ใช้ที่ตัวเองเป็น upline โดยตรง
    c.execute("SELECT id, name, owner_username FROM Customers WHERE LOWER(owner_username)=LOWER(%s) ORDER BY id DESC",
              (me["username"],))
    custs = c.fetchall()
    users = [(r[0], r[1]) for r in direct_children(c, me)]
    for r in custs:
        out.append({"key": str(r[0]), "kind": "Customer", "id": r[0], "label": f"ลูกค้า: {r[1]}"})
    for r in users:
        out.append({"key": f"user_{r[0]}", "kind": "User", "id": r[0], "label": f"user: {r[1]}"})
    return out


def get_target_name(c, t_type, t_id):
    if t_type == "User":
        c.execute("SELECT username FROM Users WHERE id=%s", (t_id,))
    else:
        c.execute("SELECT name FROM Customers WHERE id=%s", (t_id,))
    r = c.fetchone()
    return r[0] if r else None


# ============================================================ งวด / เวลาปิดรับ / หมวดหมู่

_TIME_FORMATS = ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S",
                 "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y %H:%M:%S")


def parse_timestamp(s):
    if not s:
        return None
    s = str(s).strip()
    for f in _TIME_FORMATS:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    try:
        return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def seconds_until(close_time):
    """วินาทีที่เหลือก่อนปิดรับ (ติดลบ/0 = ปิดแล้ว) หรือ None ถ้าไม่ระบุ/อ่านไม่ออก"""
    ct = parse_timestamp(close_time)
    if not ct:
        return None
    return int((ct - get_thai_time()).total_seconds())


def get_campaign(c, campaign_id):
    c.execute("SELECT id, lotto_name, draw_date, status, close_time, open_time FROM LotteryCampaigns WHERE id=%s", (campaign_id,))
    r = c.fetchone()
    if not r:
        return None
    return {"id": r[0], "lotto_name": clean_name(r[1]), "draw_date": clean_name(r[2]), "status": r[3],
            "close_time": r[4], "open_time": r[5]}


def campaign_open(camp):
    """คืน (เปิดรับไหม, เหตุผลถ้าปิด) — เช็คฝั่งเซิร์ฟเวอร์เสมอ ไม่พึ่ง JavaScript"""
    if camp["status"] != "Active":
        return False, "งวดนี้ถูกปิดโดยผู้ดูแลระบบ"
    so = seconds_until(camp.get("open_time"))          # ยังไม่ถึงเวลาเปิดรับ -> เปิดให้อัตโนมัติเมื่อถึงเวลา
    if so is not None and so > 0:
        return False, "ยังไม่ถึงเวลาเปิดรับแทง (เปิดรับ " + fmt_dt(camp.get("open_time")) + ")"
    s = seconds_until(camp["close_time"])
    if s is not None and s <= 0:
        return False, "หวยนี้ปิดรับแทงแล้ว"
    return True, ""


CATEGORY_ORDER = ["รัฐบาลไทย", "ลาว", "ฮานอย", "หุ้นต่างประเทศ", "หุ้น VIP", "อื่นๆ"]
_STOCK_KEYS = ["หุ้น", "nasdaq", "dow", "ดาวโจนส์", "s&p", "nikkei", "นิเคอิ", "dax", "เยอรมัน", "nifty", "อินเดีย",
               "kse", "ปากีสถาน", "อังกฤษ", "รัสเซีย", "จีน", "ญี่ปุ่น", "เกาหลี", "ไต้หวัน", "สิงคโปร์", "ฮั่งเส็ง",
               "ฮ่องกง", "อียิปต์", "ดาว", "ftse", "hang"]


def categorize(name):
    """จัดกลุ่มหวย: รัฐบาล / ลาว / ฮานอย / หุ้นต่างประเทศ / หุ้น VIP / อื่นๆ  (ลาว VIP อยู่กลุ่มลาว)"""
    n = (name or "").lower()
    if "รัฐบาล" in n:
        return "รัฐบาลไทย"
    if "ฮานอย" in n:
        return "ฮานอย"
    if "ลาว" in n:
        return "ลาว"
    if "vip" in n:
        return "หุ้น VIP"
    if any(k in n for k in _STOCK_KEYS):
        return "หุ้นต่างประเทศ"
    return "อื่นๆ"


_LOGOS = [
    (("ลาวพัฒนา",), "/static/" + quote("ลาวพัฒนาโลโก้.png")),
    (("รัฐบาล",), "/static/" + quote("สำนักงานสลากกินแบ่งรัฐบาล.png")),
    (("ฮานอย",), "/static/" + quote("สัญลักษณ์หวยฮานอย.png")),
    (("nasdaq",), "/static/image_4326b7.png"),
    (("s&p",), "/static/image_10cf86.png"),
    (("dow", "ดาวโจนส์"), "/static/" + quote("dow jones logo.png")),
    (("nikkei", "นิเคอิ"), "/static/image_0ff5ed.png"),
    (("dax", "เยอรมัน"), "/static/image_0ff24b.png"),
    (("nifty", "อินเดีย"), "/static/image_0feba1.jpg"),
    (("kse", "ปากีสถาน"), "/static/image_0f892c.png"),
    (("ลาว",), "https://upload.wikimedia.org/wikipedia/commons/5/56/Flag_of_Laos.svg"),
]
DEFAULT_LOGO = "https://cdn-icons-png.flaticon.com/512/10383/10383210.png"


def get_lotto_logo(lotto_name):
    n = (lotto_name or "").lower()
    for keys, url in _LOGOS:
        if any(k in n for k in keys):
            return url
    return DEFAULT_LOGO


# ============================================================ เวลางวด + การ์ดเลือกงวด (ใช้ร่วมกันสองระบบ)

def normalize_dt(s):
    """รับค่าจาก <input type=datetime-local> หรือรูปแบบอื่นที่ parse ได้ -> 'YYYY-MM-DDTHH:MM' (ผิดรูปแบบ/ว่าง = None)"""
    dt = parse_timestamp(s)
    return dt.strftime("%Y-%m-%dT%H:%M") if dt else None


def fmt_dt(s):
    dt = parse_timestamp(s)
    return dt.strftime("%d/%m/%Y %H:%M") if dt else "-"


def campaign_card_data(rows, href_fn, actions_fn=None):
    """rows: list ของ dict (id, lotto_name, draw_date, status, open_time, close_time, result_timestamp)
    คืน list ของ dict ที่ฝั่งเบราว์เซอร์ใช้วาดการ์ด/นับถอยหลัง"""
    out = []
    for r in rows:
        name, draw = clean_name(r["lotto_name"]), clean_name(r["draw_date"])
        close_s, open_s = seconds_until(r.get("close_time")), seconds_until(r.get("open_time"))
        old = r["status"] != "Active"
        rt = parse_timestamp(r.get("result_timestamp"))
        if rt and (get_thai_time() - rt).total_seconds() >= 2 * 86400:
            old = True
        if close_s is not None and close_s < -3 * 86400:
            old = True
        out.append({
            "id": r["id"], "name": name, "draw": draw, "status": r["status"], "group": categorize(name),
            "logo": get_lotto_logo(name), "href": href_fn(r), "actions": actions_fn(r) if actions_fn else [],
            "open_s": open_s, "close_s": close_s, "open_txt": fmt_dt(r.get("open_time")) if r.get("open_time") else "",
            "close_txt": fmt_dt(r.get("close_time")) if r.get("close_time") else "", "old": old,
        })
    return out


_CARDS_HTML = """
<style>
.lc-toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 14px}
.lc-seg button{border:1px solid #6c757d;background:#fff;padding:6px 14px;font-weight:600;cursor:pointer}
.lc-seg button:first-child{border-radius:8px 0 0 8px}.lc-seg button:last-child{border-radius:0 8px 8px 0;border-left:0}
.lc-seg button.active{background:#0d6efd;border-color:#0d6efd;color:#fff}
.lc-gh{font-weight:700;font-size:1.25rem;margin:22px 0 10px;padding-bottom:4px;border-bottom:3px solid #198754}
.lc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px}
.lc-card{border-radius:10px;box-shadow:0 2px 6px rgba(0,0,0,.18);overflow:hidden;display:flex;flex-direction:column}
.lc-main{display:flex;gap:12px;padding:14px;color:inherit;text-decoration:none;flex:1}
.lc-logo{width:74px;height:58px;object-fit:contain;flex:none}
.lc-name{font-size:1.3rem;font-weight:800;line-height:1.2;word-break:break-word}
.lc-draw{font-size:1.05rem;font-weight:700;margin-top:3px}
.lc-t{font-size:.85rem;margin-top:3px}.lc-cd{font-size:1.1rem;font-weight:700;margin-top:6px}
.lc-open{background:#28a745;color:#fff}.lc-open .lc-main:hover{background:#23963d}
.lc-closed,.lc-upcoming{background:#fff;color:#222;border:1px solid #d9d9d9}.lc-upcoming{border-left:6px solid #0d6efd}
.lc-done{background:#ececec;color:#666;border:1px solid #d0d0d0}
.lc-closed .lc-cd{color:#dc3545}.lc-upcoming .lc-cd{color:#0d6efd}
.lc-act{display:flex;gap:6px;padding:6px 10px;background:rgba(0,0,0,.08)}
.lc-act a{font-size:.78rem;font-weight:700;color:#000;background:#fff;border-radius:5px;padding:2px 8px;text-decoration:none}
</style>
<div class="lc-toolbar">
  <div class="lc-seg"><button type="button" data-mode="time">⏱ เรียงตามเวลาปิดรับ</button><button type="button" data-mode="group">🗂 แยกกลุ่มหวย</button></div>
  {% if show_old_toggle %}<label class="fw-bold small"><input type="checkbox" id="lc-old"> แสดงงวดที่ปิดแล้ว / เก่า</label>{% endif %}
  <span class="small text-muted" id="lc-count"></span>
</div>
<div id="lc-root"></div>
<script type="application/json" id="lc-data">{{ payload|tojson }}</script>
<script>
(function(){
var P=JSON.parse(document.getElementById('lc-data').textContent),cards=P.cards,root=document.getElementById('lc-root');
var t0=Date.now(),mode='time',showOld=false,btns=document.querySelectorAll('.lc-seg button');
try{mode=localStorage.getItem('lc_mode')||'time';}catch(e){}
function el(){return (Date.now()-t0)/1000;}
function stOf(c){if(c.status!=='Active')return 'done';var e=el();
 if(c.open_s!==null&&c.open_s-e>0)return 'upcoming';
 if(c.close_s!==null&&c.close_s-e<=0)return 'closed';return 'open';}
function p2(n){return (n<10?'0':'')+n;}
function fmt(s){s=Math.max(0,Math.floor(s));var d=Math.floor(s/86400);s%=86400;
 return (d?d+' วัน ':'')+p2(Math.floor(s/3600))+':'+p2(Math.floor(s%3600/60))+':'+p2(s%60);}
function cd(c,st){var e=el();
 if(st==='open')return c.close_s===null?'เปิดรับแทง':'ปิดรับใน '+fmt(c.close_s-e);
 if(st==='upcoming')return 'เปิดรับใน '+fmt(c.open_s-e);
 return st==='closed'?'ปิดรับแล้ว':'ปิดงวดแล้ว';}
function rank(c,st){var e=el();
 if(st==='open')return [0,c.close_s===null?1e12:c.close_s-e];
 if(st==='upcoming')return [1,c.open_s-e];
 if(st==='closed')return [2,e-(c.close_s||0)];return [3,0];}
function cmp(a,b){var x=rank(a.c,a.st),y=rank(b.c,b.st);return x[0]-y[0]||x[1]-y[1];}
function mk(tag,cls,txt){var n=document.createElement(tag);if(cls)n.className=cls;if(txt!==undefined)n.textContent=txt;return n;}
function build(c,st){
 var d=mk('div','lc-card lc-'+st),a=mk(c.href&&st!=='done'?'a':'div','lc-main');
 if(a.tagName==='A')a.href=c.href;
 var im=mk('img','lc-logo');im.alt='';im.src=c.logo;im.onerror=function(){this.onerror=null;this.src=P.default_logo;};a.appendChild(im);
 var b=mk('div');b.appendChild(mk('div','lc-name',c.name));b.appendChild(mk('div','lc-draw','งวด '+c.draw));
 if(c.open_txt)b.appendChild(mk('div','lc-t','เวลาเปิดรับ '+c.open_txt));
 b.appendChild(mk('div','lc-t','เวลาปิดรับ '+(c.close_txt||'-')));
 var s=mk('div','lc-cd',cd(c,st));s.setAttribute('data-cd',c.id);b.appendChild(s);a.appendChild(b);d.appendChild(a);
 if(c.actions&&c.actions.length){var x=mk('div','lc-act');c.actions.forEach(function(t){var l=mk('a','',t[0]);l.href=t[1];x.appendChild(l);});d.appendChild(x);}
 return d;}
function grid(list){var g=mk('div','lc-grid');list.forEach(function(o){g.appendChild(build(o.c,o.st));});return g;}
function render(){
 root.textContent='';
 var list=cards.map(function(c){return {c:c,st:stOf(c)};}).filter(function(o){return showOld||!(o.c.old||o.st==='done');}).sort(cmp);
 document.getElementById('lc-count').textContent=list.length+' งวด';
 if(!list.length){root.appendChild(mk('div','alert alert-warning text-center fw-bold','ยังไม่มีงวดหวยที่เปิดอยู่ในขณะนี้'));return;}
 if(mode==='group'){P.order.forEach(function(g){var l=list.filter(function(o){return o.c.group===g;});
  if(l.length){root.appendChild(mk('div','lc-gh','🎯 '+g+' ('+l.length+')'));root.appendChild(grid(l));}});}
 else root.appendChild(grid(list));
 cards.forEach(function(c){c._st=stOf(c);});}
function tick(){var ch=false;cards.forEach(function(c){if(c._st!==stOf(c))ch=true;});
 if(ch){render();return;}
 cards.forEach(function(c){var n=root.querySelector('[data-cd="'+c.id+'"]');if(n)n.textContent=cd(c,stOf(c));});}
btns.forEach(function(b){b.onclick=function(){mode=b.getAttribute('data-mode');try{localStorage.setItem('lc_mode',mode);}catch(e){}
 btns.forEach(function(x){x.classList.toggle('active',x===b);});render();};
 b.classList.toggle('active',b.getAttribute('data-mode')===mode);});
var o=document.getElementById('lc-old');if(o)o.onchange=function(){showOld=o.checked;render();};
render();setInterval(tick,1000);
})();
</script>
"""


def render_campaign_cards(rows, href_fn, actions_fn=None, show_old_toggle=False):
    """HTML (ปลอดภัยต่อ XSS: ข้อมูลส่งเป็น JSON แล้ววาดด้วย textContent) — เอาไปแทรกในหน้าได้เลย"""
    payload = {"cards": campaign_card_data(rows, href_fn, actions_fn), "order": CATEGORY_ORDER,
               "default_logo": DEFAULT_LOGO}
    return _Jinja(_CARDS_HTML, autoescape=True).render(payload=payload, show_old_toggle=show_old_toggle)


# ============================================================ เลขอั้น

_INVISIBLE = "[[:space:]\u00a0\u200b\u200c\u200d\ufeff]"      # รูปแบบ regex ของ Postgres


def clean_name(x):
    """ตัดช่องว่าง/อักขระล่องหนที่หัวท้ายชื่อ (ชื่อหวยในฐานข้อมูลเก่าอาจมีตัวแฝงทำให้เทียบกันไม่ตรง)"""
    return re.sub(r"^[\s\u00a0\u200b-\u200d\ufeff]+|[\s\u00a0\u200b-\u200d\ufeff]+$", "", str(x or ""))


def _name_key(x):
    """ชื่อสำหรับเทียบ: ตัดอักขระว่าง/ล่องหนทุกตำแหน่ง"""
    return re.sub(r"[\s\u00a0\u200b-\u200d\ufeff]+", "", str(x or ""))


_LOTTO_COND = f"(lotto_name IS NULL OR regexp_replace(lotto_name, '{_INVISIBLE}', '', 'g') = %s)"


def _draw_match(a, b):
    """งวดตรงกันแบบเดียวกับที่ระบบหลักใช้ (เท่ากัน หรือ มีข้อความอีกฝั่งอยู่ภายใน)"""
    a, b = (a or "").strip().lower(), (b or "").strip().lower()
    return bool(a) and bool(b) and (a == b or a in b or b in a)


def get_blocked_map(c, lotto_name, draw_date):
    """{เลข: สถานะ}  — 'ปิดรับ' ชนะ 'จ่ายครึ่ง' ถ้าเลขเดียวกันมีทั้งสองสถานะ
    ใช้ได้กับแถวเก่าที่ยังไม่มี lotto_name (NULL = อั้นทุกตลาดในงวดนั้น)"""
    c.execute(
        "SELECT raw_num, status FROM BlockedNumbers "
        "WHERE (draw_date=%s OR draw_date ILIKE %s) AND " + _LOTTO_COND,
        (draw_date, f"%{like_escape(draw_date)}%", _name_key(lotto_name)),
    )
    out = {}
    for num, st in c.fetchall():
        if not num:
            continue
        k = str(num).strip()
        if out.get(k) == "ปิดรับ":
            continue
        out[k] = str(st)
    return out


def get_blocked_display(c, lotto_name, draw_date):
    """คืน (ปิดรับ, 3ตัวจ่ายครึ่ง, 2ตัวจ่ายครึ่ง) เป็นข้อความคั่นด้วยคอมม่า"""
    base = ("SELECT raw_num, status, type FROM BlockedNumbers "
            "WHERE (draw_date=%s OR draw_date ILIKE %s) AND " + _LOTTO_COND)
    args = (draw_date, f"%{like_escape(draw_date)}%", _name_key(lotto_name))
    c.execute(base + " AND is_raw = TRUE", args)
    rows = c.fetchall()
    if not rows:
        c.execute(base, args)
        rows = c.fetchall()
    closed, d3, d2 = [], [], []
    seen = set()
    for num, st, tp in rows:
        if not num:
            continue
        s = str(num).strip()
        if st == "ปิดรับ":
            bucket = closed
        elif len(s) == 3 or tp == "3ตัว":
            bucket = d3
        elif len(s) == 2 or tp == "2ตัว":
            bucket = d2
        else:
            continue
        if (id(bucket), s) not in seen:
            seen.add((id(bucket), s))
            bucket.append(s)
    return ", ".join(closed), ", ".join(d3), ", ".join(d2)


# ============================================================ เลขที่บิล

_TH_MONTHS = {
    "มกราคม": 1, "กุมภาพันธ์": 2, "มีนาคม": 3, "เมษายน": 4, "พฤษภาคม": 5, "มิถุนายน": 6,
    "กรกฎาคม": 7, "สิงหาคม": 8, "กันยายน": 9, "ตุลาคม": 10, "พฤศจิกายน": 11, "ธันวาคม": 12,
    "ม.ค.": 1, "ก.พ.": 2, "มี.ค.": 3, "เม.ย.": 4, "พ.ค.": 5, "มิ.ย.": 6,
    "ก.ค.": 7, "ส.ค.": 8, "ก.ย.": 9, "ต.ค.": 10, "พ.ย.": 11, "ธ.ค.": 12,
}


def extract_date_to_string(draw_date):
    """'16 ตุลาคม 2026' / '16/10/2026' / '2026-10-16' -> '161026'  (รองรับปี พ.ศ.)"""
    s = str(draw_date or "")
    day = month = year = None
    for name, num in sorted(_TH_MONTHS.items(), key=lambda kv: -len(kv[0])):
        if name in s:
            month = num
            nums = re.findall(r"\d+", s)
            if nums:
                day = int(nums[0])
            if len(nums) >= 2:
                year = int(nums[-1])
            break
    if month is None:
        nums = re.findall(r"\d+", s)
        if len(nums) >= 3:
            if len(nums[0]) == 4:      # ISO: ปี-เดือน-วัน
                year, month, day = int(nums[0]), int(nums[1]), int(nums[2])
            else:
                day, month, year = int(nums[0]), int(nums[1]), int(nums[2])
    if day and month and year:
        if year > 2400:
            year -= 543
        return f"{day:02d}{month:02d}{year % 100:02d}"
    return get_thai_time().strftime("%d%m%y")


def bill_prefix(lotto_name):
    n = str(lotto_name or "").lower()
    if "รัฐบาล" in n or "ไทย" in n:
        return "TH"
    if "ลาว" in n:
        return "LO"
    if "ฮานอย" in n or "เวียดนาม" in n:
        return "HN"
    if "มาเลย์" in n:
        return "MY"
    if "หุ้น" in n or any(k in n for k in ("nasdaq", "dow", "s&p", "nikkei", "dax", "nifty", "kse")):
        return "ST"
    if "ยี่กี" in n or "ปิงปอง" in n:
        return "YG"
    return "OT"


def generate_bill_no(c, lotto_name, draw_date, t_type, t_id):
    """เลขที่บิลไม่ซ้ำข้ามประเภท: ลูกค้า=C<id>, ผู้ใช้=U<id>  เช่น TH161026-C5-B01
    ลำดับ B?? นับตามหวย+งวด+ผู้ซื้อ และตรวจซ้ำก่อนคืนค่า (เรียกภายใน transaction เดียวกับตอน INSERT)"""
    tag = ("U" if t_type == "User" else "C") + str(t_id)
    head = f"{bill_prefix(lotto_name)}{extract_date_to_string(draw_date)}-{tag}-B"
    c.execute(
        "SELECT COUNT(DISTINCT bill_no) FROM Transactions "
        "WHERE customer_id=%s AND customer_type=%s AND lotto_name=%s AND draw_date=%s",
        (t_id, t_type, lotto_name, draw_date),
    )
    seq = (c.fetchone()[0] or 0) + 1
    while True:
        bill_no = f"{head}{seq:02d}"
        c.execute("SELECT 1 FROM Transactions WHERE bill_no=%s LIMIT 1", (bill_no,))
        if not c.fetchone():
            return bill_no
        seq += 1


# ============================================================ ยอดขายเรียลไทม์ (แอดมิน) + เจาะลึกตามสายงาน

BUILD = "2026-11-25.1"      # หมายเลขรุ่นของ common.py (แสดงในหน้ายอดขายสดและ log ตอนสตาร์ต)

_SALES_COLS = "COALESCE(SUM(amount),0), COALESCE(SUM(discount),0), COALESCE(SUM(net),0), COUNT(DISTINCT bill_no), COUNT(*)"


def _sales_filter(c, f):
    """f: '' = ทั้งหมด | 'today' = วันนี้ | 'c:<id>' = งวดนั้น  -> (เงื่อนไข SQL, พารามิเตอร์)"""
    f = (f or "").strip()
    if f == "today":
        return " AND timestamp LIKE %s", (get_thai_time().strftime("%d/%m/%Y") + "%",)
    if f.startswith("c:"):
        camp = get_campaign(c, int(f[2:])) if f[2:].isdigit() else None
        if camp:
            return (" AND draw_date = %s AND regexp_replace(lotto_name, '" + _INVISIBLE + "', '', 'g') = %s",
                    (camp["draw_date"], _name_key(camp["lotto_name"])))
    return "", ()


def _agg(row):
    return {"amount": float(row[0] or 0), "discount": float(row[1] or 0), "net": float(row[2] or 0),
            "bills": int(row[3] or 0), "items": int(row[4] or 0)}


def _zero():
    return {"amount": 0.0, "discount": 0.0, "net": 0.0, "bills": 0, "items": 0}


def _add(a, b):
    for k in a:
        a[k] += b[k]


def live_sales_options(c):
    out = [{"value": "", "label": "ทุกงวด"}, {"value": "today", "label": "เฉพาะรายการที่คีย์วันนี้"}]
    c.execute("SELECT id, lotto_name, draw_date FROM LotteryCampaigns ORDER BY id DESC LIMIT 60")
    for r in c.fetchall():
        out.append({"value": f"c:{r[0]}", "label": f"{clean_name(r[1])} งวด {clean_name(r[2])}"})
    return out


def live_sales_data(c, root, node, f=""):
    """ยอดขายของ 'node' (username) แยกเป็นแถว: ลูกค้าของเขา / บัญชีตัวเอง / ผู้ใช้ใต้สายงานโดยตรง (รวมยอดทั้งสายของคนนั้น)
    ยอดรวมของแถวทั้งหมด = ยอดของทั้งสายที่ node ดูแล (ไม่นับซ้ำ)  root = แอดมินที่เรียกดู (จำกัดให้ดูได้เฉพาะภายใต้ root)"""
    nu = get_user(c, node) or get_user(c, root)
    if not nu:
        return None
    sub_root = get_subtree(c, root)
    if nu["username"] not in sub_root:
        nu = get_user(c, root)
    node = nu["username"]
    where, wargs = _sales_filter(c, f)
    rows, total = [], _zero()

    # 1) ลูกค้าของ node (ที่ node คีย์ให้)
    c.execute(f"SELECT customer_id, MAX(customer_name), {_SALES_COLS} FROM Transactions "
              f"WHERE username=%s AND COALESCE(customer_type,'Customer')='Customer'{where} GROUP BY customer_id",
              (node, *wargs))
    for r in c.fetchall():
        d = _agg(r[2:])
        rows.append({"kind": "customer", "name": r[1] or f"ลูกค้า #{r[0]}", "key": None, **d})

    # 2) ผู้ใช้ใต้สายงานโดยตรง (child) และยอดที่ node คีย์ให้ผู้ใช้เหล่านั้น
    children = {r[1]: {"id": r[0], "role": norm_role(r[2])} for r in direct_children(c, nu)}
    by_child = {u: _zero() for u in children}
    if children:
        sub = [u for u in get_subtree(c, node) if u != node]
        owner_of = {}
        if sub:
            c.execute("SELECT username, parent_user FROM Users WHERE username = ANY(%s)", (sub,))
            parent = {r[0]: r[1] for r in c.fetchall()}
            for u in sub:                                   # หา child ชั้นแรกที่เป็นต้นสายของ u (หรือ u เอง)
                cur, guard = u, 0
                while cur and cur not in children and guard < 50:
                    cur, guard = (parent.get(cur) or None), guard + 1
                if cur in children:
                    owner_of[u] = cur
            c.execute(f"SELECT username, {_SALES_COLS} FROM Transactions WHERE username = ANY(%s){where} GROUP BY username",
                      (sub, *wargs))
            for r in c.fetchall():
                ch = owner_of.get(r[0])
                if ch:
                    _add(by_child[ch], _agg(r[1:]))
    c.execute(f"SELECT customer_id, {_SALES_COLS} FROM Transactions WHERE username=%s AND customer_type='User'{where} "
              f"GROUP BY customer_id", (node, *wargs))
    id_to_child = {v["id"]: u for u, v in children.items()}
    for r in c.fetchall():
        d = _agg(r[1:])
        try:
            cid = int(r[0])
        except (TypeError, ValueError):
            cid = None
        if cid in id_to_child:
            _add(by_child[id_to_child[cid]], d)
        elif cid == nu["id"]:
            rows.append({"kind": "self", "name": f"บัญชีตัวเอง ({node})", "key": None, **d})
        else:
            rows.append({"kind": "other", "name": "ผู้ใช้อื่นนอกสายตรง", "key": None, **d})
    for u, d in by_child.items():
        rows.append({"kind": "user", "name": u, "key": u, "role": children[u]["role"], **d})

    # 3) ยอดที่ upline คีย์ให้บัญชีนี้ (แสดงตอนเจาะลึกเข้ามาในบัญชี)
    if nu.get("parent_user") and node != root:
        c.execute(f"SELECT {_SALES_COLS} FROM Transactions WHERE LOWER(username)=LOWER(%s) AND customer_type='User' "
                  f"AND customer_id=%s{where}", (nu["parent_user"], nu["id"], *wargs))
        d = _agg(c.fetchone())
        if d["items"]:
            rows.append({"kind": "upline", "name": f"คีย์ให้โดย upline ({nu['parent_user']})", "key": None, **d})

    # ลูกค้าของ node ที่ยังไม่มียอด แสดงเป็น 0 เพื่อให้เห็นครบทุกราย
    c.execute("SELECT id, name FROM Customers WHERE LOWER(owner_username)=LOWER(%s) ORDER BY name", (node,))
    have = {r["name"] for r in rows if r["kind"] == "customer"}
    for cid, cname in c.fetchall():
        if (cname or f"ลูกค้า #{cid}") not in have:
            rows.append({"kind": "customer", "name": cname or f"ลูกค้า #{cid}", "key": None, **_zero()})
    rows = [r for r in rows if r["items"] or r["kind"] in ("user", "customer")]
    for r in rows:
        _add(total, {k: r[k] for k in total})
    rows.sort(key=lambda r: (-r["amount"], r["name"]))
    # เส้นทาง (breadcrumb) จาก root ถึง node
    path, cur, guard = [], node, 0
    while cur and guard < 50:
        path.append(cur)
        if cur.lower() == root.lower():
            break
        u = get_user(c, cur)
        cur, guard = (u or {}).get("parent_user"), guard + 1
    path.reverse()
    return {"node": node, "path": path, "rows": rows, "total": total, "build": BUILD,
            "updated": get_thai_time().strftime("%d/%m/%Y %H:%M:%S")}


_LIVE_HTML = """
<style>
.ls-wrap{max-width:1250px;margin:0 auto}
.ls-bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:12px}
.ls-crumb button{border:0;background:none;color:#0d6efd;font-weight:700;padding:2px 4px;cursor:pointer}
.ls-crumb span.sep{color:#888}.ls-crumb button:last-child{color:#222;cursor:default}
.ls-table th{background:#212529;color:#fff;text-align:center;white-space:nowrap}
.ls-table td.num{text-align:right;font-variant-numeric:tabular-nums}
.ls-table tr.drill{cursor:pointer}.ls-table tr.drill:hover{background:#fff3cd}
.ls-bar2{height:8px;background:#e9ecef;border-radius:4px;min-width:90px}.ls-bar2 i{display:block;height:8px;background:#198754;border-radius:4px}
.ls-pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:.75rem;font-weight:700;color:#fff}
.ls-user{background:#0d6efd}.ls-customer{background:#6c757d}.ls-self,.ls-upline,.ls-other{background:#b58900}
.ls-live{display:inline-block;width:10px;height:10px;border-radius:50%;background:#198754;margin-right:6px;animation:lsp 1.2s infinite}
@keyframes lsp{50%{opacity:.25}}
.ls-tot td{font-weight:800;background:#f8f9fa}
</style>
<div class="ls-wrap">
  <div class="ls-bar">
    <label class="fw-bold">ช่วงข้อมูล:</label>
    <select id="ls-f" class="form-select form-select-sm" style="max-width:340px">
      {% for o in options %}<option value="{{ o.value }}">{{ o.label }}</option>{% endfor %}
    </select>
    <label class="small"><input type="checkbox" id="ls-auto" checked> รีเฟรชอัตโนมัติทุก 5 วินาที</label>
    <button class="btn btn-sm btn-outline-primary" id="ls-now" type="button">🔄 รีเฟรชตอนนี้</button>
    <span class="small text-muted"><span class="ls-live"></span><span id="ls-upd">กำลังโหลด...</span></span>
  </div>
  <div class="ls-crumb mb-2" id="ls-path"></div>
  <div class="alert alert-info py-1 small mb-2">💡 ดับเบิลคลิกที่แถว <b>สายงาน</b> (สีน้ำเงิน) เพื่อดูว่ายอดมาจากผู้ซื้อ/ผู้ใช้ใต้สายงานรายใดบ้าง · บนมือถือแตะปุ่ม "เจาะลึก"</div>
  <div class="table-responsive"><table class="table table-bordered table-sm ls-table bg-white">
    <thead><tr><th>ชื่อ</th><th>ประเภท</th><th>ยอดแทง</th><th>ส่วนลด</th><th>สุทธิ</th><th>บิล</th><th>รายการ</th><th style="width:140px">สัดส่วน</th><th></th></tr></thead>
    <tbody id="ls-body"></tbody>
  </table></div>
</div>
<script>
(function(){
var URL0="{{ data_url }}",node="",busy=false,body=document.getElementById('ls-body'),sel=document.getElementById('ls-f');
var KIND={user:'สายงาน',customer:'ลูกค้า',self:'บัญชีตัวเอง',upline:'คีย์โดย upline',other:'อื่นๆ'};
function nf(v){return Number(v).toLocaleString('th-TH',{minimumFractionDigits:2,maximumFractionDigits:2});}
function mk(t,c,x){var n=document.createElement(t);if(c)n.className=c;if(x!==undefined)n.textContent=x;return n;}
function load(){if(busy)return;busy=true;
 var u=URL0+(URL0.indexOf('?')<0?'?':'&')+'node='+encodeURIComponent(node)+'&f='+encodeURIComponent(sel.value);
 fetch(u,{credentials:'same-origin'}).then(function(r){if(!r.ok)throw new Error(r.status);return r.json();}).then(function(d){busy=false;draw(d);})
 .catch(function(){busy=false;document.getElementById('ls-upd').textContent='โหลดข้อมูลไม่สำเร็จ (จะลองใหม่)';});}
function go(n){node=n;load();}
function draw(d){node=d.node;
 var p=document.getElementById('ls-path');p.textContent='';
 d.path.forEach(function(n,i){if(i){p.appendChild(mk('span','sep',' › '));}var b=mk('button','',i===0?'🏠 '+n:n);b.type='button';b.onclick=function(){go(n);};p.appendChild(b);});
 body.textContent='';var tot=d.total.amount||1;
 d.rows.forEach(function(r){var tr=mk('tr',r.key?'drill':'');
  var nm=mk('td','',r.name+(r.role?' ('+r.role+')':''));tr.appendChild(nm);
  var k=mk('td');k.style.textAlign='center';k.appendChild(mk('span','ls-pill ls-'+r.kind,KIND[r.kind]||r.kind));tr.appendChild(k);
  [r.amount,r.discount,r.net].forEach(function(v){tr.appendChild(mk('td','num',nf(v)));});
  tr.appendChild(mk('td','num',r.bills));tr.appendChild(mk('td','num',r.items));
  var bar=mk('td');var o=mk('div','ls-bar2'),i=mk('i');i.style.width=Math.min(100,r.amount/tot*100)+'%';o.appendChild(i);bar.appendChild(o);tr.appendChild(bar);
  var a=mk('td');a.style.textAlign='center';
  if(r.key){tr.ondblclick=function(){go(r.key);};var bt=mk('button','btn btn-sm btn-outline-primary py-0','🔍 เจาะลึก');bt.type='button';bt.onclick=function(){go(r.key);};a.appendChild(bt);}
  tr.appendChild(a);body.appendChild(tr);});
 if(!d.rows.length){var tr=mk('tr'),td=mk('td','text-center text-muted py-3','ยังไม่มียอดขายในช่วงนี้');td.colSpan=9;tr.appendChild(td);body.appendChild(tr);}
 var t=mk('tr','ls-tot');t.appendChild(mk('td','','รวมทั้งหมด'));t.appendChild(mk('td'));
 [d.total.amount,d.total.discount,d.total.net].forEach(function(v){t.appendChild(mk('td','num',nf(v)));});
 t.appendChild(mk('td','num',d.total.bills));t.appendChild(mk('td','num',d.total.items));t.appendChild(mk('td'));t.appendChild(mk('td'));body.appendChild(t);
 document.getElementById('ls-upd').textContent='อัปเดตล่าสุด '+d.updated+' · รุ่น '+(d.build||'เก่า')+' · พบ '+d.rows.length+' รายการ';}
sel.onchange=load;document.getElementById('ls-now').onclick=load;
setInterval(function(){if(document.getElementById('ls-auto').checked&&!document.hidden)load();},5000);
load();
})();
</script>
"""


def render_live_sales(c, data_url):
    return _Jinja(_LIVE_HTML, autoescape=True).render(options=live_sales_options(c), data_url=data_url)


# ============================================================ เงินรางวัล (ใช้ตรรกะเดียวกับหน้า results ของระบบหลัก)

def row_payout(num, ttype, amt, rate, prize_1, bottom_2, half_set):
    num, ttype = str(num).strip(), str(ttype).strip()
    win = False
    if ttype == "3ตัวตรง":
        win = bool(prize_1) and num == prize_1
    elif ttype == "3ตัวโต๊ด":
        win = bool(prize_1) and sorted(num) == sorted(prize_1) and num != prize_1
    elif ttype == "2ตัวบน":
        win = bool(prize_1) and len(prize_1) >= 2 and num == prize_1[-2:]
    elif ttype == "2ตัวล่าง":
        win = bool(bottom_2) and num == bottom_2
    elif ttype == "วิ่งบน":
        win = bool(prize_1) and num in prize_1
    elif ttype == "วิ่งล่าง":
        win = bool(bottom_2) and num in bottom_2
    if not win:
        return 0.0
    rate = float(rate or 0)
    if num in half_set:
        rate /= 2.0
    return float(amt or 0) * rate


def find_result(results, draw_date):
    """results = {draw_date: (prize_1, bottom_2)} -> (prize_1, bottom_2) หรือ None"""
    if draw_date in results:
        return results[draw_date]
    for k, v in results.items():
        if _draw_match(draw_date, k):
            return v
    return None


# ============================================================ Migration (รันที่เดียว ใช้ IF NOT EXISTS ทั้งหมด)

def _rate_cols(table):
    return [f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {k} NUMERIC DEFAULT {RATE_DEFAULTS[k]}"
            for k in RATE_KEYS]


MIGRATIONS = [
    # ---- ตารางหลัก (นิยามเดียวกับระบบหลัก ใครรันก่อนก็ได้ผลเหมือนกัน) ----
    "CREATE TABLE IF NOT EXISTS Users (id SERIAL PRIMARY KEY, username TEXT, password TEXT, "
    "role TEXT DEFAULT 'Member', parent_user TEXT)",
    "CREATE TABLE IF NOT EXISTS Customers (id SERIAL PRIMARY KEY, name TEXT, owner_username TEXT, "
    "discount_type INTEGER DEFAULT 1)",
    "CREATE TABLE IF NOT EXISTS LotteryCampaigns (id SERIAL PRIMARY KEY, lotto_name TEXT, draw_date TEXT, "
    "status TEXT DEFAULT 'Active', close_time TEXT)",
    "CREATE TABLE IF NOT EXISTS BlockedNumbers (id SERIAL PRIMARY KEY, draw_date TEXT, raw_num TEXT, "
    "status TEXT, type TEXT)",
    "CREATE TABLE IF NOT EXISTS TempDraft (id SERIAL PRIMARY KEY, username TEXT, customer_id TEXT, "
    "customer_type TEXT, num TEXT, type TEXT)",
    "CREATE TABLE IF NOT EXISTS Transactions (id SERIAL PRIMARY KEY, draw_date TEXT, timestamp TEXT, "
    "username TEXT, customer_id INTEGER, customer_name TEXT, customer_type TEXT, bill_no TEXT, num TEXT, "
    "type TEXT, amount NUMERIC DEFAULT 0, status TEXT, discount NUMERIC DEFAULT 0, net NUMERIC DEFAULT 0, "
    "payout_rate NUMERIC DEFAULT 0, lotto_name TEXT)",
    "CREATE TABLE IF NOT EXISTS DrawResults (id SERIAL PRIMARY KEY, draw_date TEXT UNIQUE, prize_1 TEXT, bottom_2 TEXT)",
    "CREATE TABLE IF NOT EXISTS CancelledTransactions (id SERIAL PRIMARY KEY, orig_id INTEGER, draw_date TEXT, timestamp TEXT, "
    "username TEXT, customer_id INTEGER, customer_name TEXT, customer_type TEXT, bill_no TEXT, num TEXT, type TEXT, "
    "amount NUMERIC DEFAULT 0, status TEXT, discount NUMERIC DEFAULT 0, net NUMERIC DEFAULT 0, payout_rate NUMERIC DEFAULT 0, "
    "lotto_name TEXT, cancelled_by TEXT, cancelled_at TEXT, reason TEXT)",
    "ALTER TABLE Users ADD COLUMN IF NOT EXISTS credit_enabled BOOLEAN DEFAULT FALSE",
    "ALTER TABLE Customers ADD COLUMN IF NOT EXISTS credit_enabled BOOLEAN DEFAULT FALSE",
    "ALTER TABLE Customers ADD COLUMN IF NOT EXISTS link_code TEXT",
    "UPDATE Customers SET link_code = upper(substr(md5(random()::text || id::text), 1, 6)) WHERE link_code IS NULL OR link_code = ''",
    "CREATE TABLE IF NOT EXISTS CreditLedger (id SERIAL PRIMARY KEY, target_type TEXT, target_id INTEGER, delta NUMERIC(14,2), "
    "kind TEXT, bill_no TEXT, note TEXT, by_user TEXT, created_at TEXT)",
    "CREATE INDEX IF NOT EXISTS ix_creditledger_target ON CreditLedger (target_type, target_id)",
    "CREATE TABLE IF NOT EXISTS ChannelSettings (id SERIAL PRIMARY KEY, owner_username TEXT, channel TEXT, webhook_key TEXT, "
    "config TEXT, enabled BOOLEAN DEFAULT TRUE, updated_at TEXT)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_channelsettings_owner ON ChannelSettings (owner_username, channel)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_channelsettings_key ON ChannelSettings (webhook_key)",
    "CREATE TABLE IF NOT EXISTS ChannelLinks (id SERIAL PRIMARY KEY, channel TEXT, external_id TEXT, owner_username TEXT, "
    "customer_id INTEGER, campaign_id INTEGER, created_at TEXT)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_channellinks ON ChannelLinks (channel, external_id, owner_username)",
    "CREATE TABLE IF NOT EXISTS AgentSettlements (id SERIAL PRIMARY KEY, agent_username VARCHAR(100), "
    "target_name VARCHAR(100), amount NUMERIC(12,2), settle_type VARCHAR(20), note TEXT, timestamp TEXT)",
    # เรตแยกหวย: คีย์มาตรฐานคือ target_id ("12" = ลูกค้า, "user_5" = ผู้ใช้); เก็บ customer_id ไว้ให้ระบบหลักเดิมยังทำงานได้
    "CREATE TABLE IF NOT EXISTS CustomerLottoRates (id SERIAL PRIMARY KEY, customer_id INT, "
    "target_type VARCHAR(20), target_id VARCHAR(100), lotto_name VARCHAR(100))",

    # ---- คอลัมน์ของ Users / Customers (ชุดเดียวกัน ชื่อเดียวกัน) ----
    "ALTER TABLE Users ADD COLUMN IF NOT EXISTS parent_user VARCHAR(100)",
    "ALTER TABLE Customers ADD COLUMN IF NOT EXISTS owner_username TEXT",
    *_rate_cols("Users"),
    *_rate_cols("Customers"),
    # ข้อมูลเก่าที่ระบบตัวแทนเคยเก็บไว้ใน parent_username
    "UPDATE Users SET parent_user = parent_username WHERE parent_user IS NULL AND parent_username IS NOT NULL",

    # ---- LotteryCampaigns / BlockedNumbers / DrawResults ----
    "ALTER TABLE LotteryCampaigns ADD COLUMN IF NOT EXISTS close_time TEXT",
    "ALTER TABLE LotteryCampaigns ADD COLUMN IF NOT EXISTS open_time TEXT",
    "ALTER TABLE LotteryCampaigns ALTER COLUMN close_time TYPE TEXT USING close_time::text",
    "ALTER TABLE LotteryCampaigns ADD COLUMN IF NOT EXISTS result_timestamp TEXT",
    "ALTER TABLE BlockedNumbers ADD COLUMN IF NOT EXISTS is_raw BOOLEAN DEFAULT FALSE",
    "ALTER TABLE BlockedNumbers ADD COLUMN IF NOT EXISTS lotto_name TEXT",
    "ALTER TABLE DrawResults ADD COLUMN IF NOT EXISTS lotto_name TEXT",

    # ---- TempDraft: ผูกโพยร่างกับหวย/งวด ----
    "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS amt_teng NUMERIC DEFAULT 0",
    "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS amt_tod NUMERIC DEFAULT 0",
    "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS payout_rate NUMERIC DEFAULT 0",
    "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS discount NUMERIC DEFAULT 0",   # หน่วย = บาท (ทั้งสองระบบ)
    "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS net NUMERIC DEFAULT 0",
    "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'ปกติ'",
    "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS lotto_name TEXT",
    "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS draw_date TEXT",
    """DO $$ BEGIN
         IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tempdraft'
                    AND column_name='customer_id' AND data_type NOT IN ('text','character varying')) THEN
           ALTER TABLE TempDraft ALTER COLUMN customer_id TYPE TEXT USING customer_id::text;
         END IF;
       END $$""",
    # โพยร่างที่ระบบตัวแทนรุ่นเก่าเก็บ customer_id เป็น 'user_5' + type 'Customer' -> แปลงเป็นรูปแบบกลาง
    "UPDATE TempDraft SET customer_type='User', customer_id=SUBSTRING(customer_id FROM 6) "
    "WHERE customer_id LIKE 'user!_%' ESCAPE '!'",

    # ---- Transactions ----
    "ALTER TABLE Transactions ADD COLUMN IF NOT EXISTS lotto_name TEXT",

    # ---- CustomerLottoRates: ทำให้เป็นโครงสร้างเดียวกัน ----
    "ALTER TABLE CustomerLottoRates ADD COLUMN IF NOT EXISTS customer_id INT",
    "ALTER TABLE CustomerLottoRates ADD COLUMN IF NOT EXISTS target_type VARCHAR(20) DEFAULT 'Customer'",
    "ALTER TABLE CustomerLottoRates ADD COLUMN IF NOT EXISTS target_id VARCHAR(100)",
    *_rate_cols("CustomerLottoRates"),
    "ALTER TABLE CustomerLottoRates ALTER COLUMN lotto_name DROP NOT NULL",
    "UPDATE CustomerLottoRates SET target_id = customer_id::text WHERE target_id IS NULL AND customer_id IS NOT NULL",
    "DELETE FROM CustomerLottoRates a USING CustomerLottoRates b "
    "WHERE a.id < b.id AND a.target_id = b.target_id AND a.lotto_name = b.lotto_name",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_rates_target_lotto ON CustomerLottoRates(target_id, lotto_name)",

    # ---- DrawResults: ระบบหลักใช้ ON CONFLICT (draw_date) จึงต้องมี unique ----
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_drawresults_date ON DrawResults(draw_date)",
    # บัญชีเก่าที่ไม่มี upline จริง (parent_user ว่าง / "-" / ชื่อที่ไม่มีในระบบ) -> ให้เป็นสายตรงของแอดมินคนแรก
    "UPDATE Users SET parent_user = (SELECT username FROM Users WHERE LOWER(role) = 'admin' ORDER BY id LIMIT 1) "
    "WHERE LOWER(role) <> 'admin' AND NOT EXISTS (SELECT 1 FROM Users pp WHERE LOWER(pp.username) = LOWER(Users.parent_user)) "
    "AND EXISTS (SELECT 1 FROM Users WHERE LOWER(role) = 'admin')",
    # ---- ล้างช่องว่าง/อักขระล่องหนที่หัวท้ายชื่อหวยและวันที่งวด (ทำให้เทียบชื่อไม่ตรงข้ามระบบ) — รันซ้ำได้ ----
    "UPDATE LotteryCampaigns SET lotto_name = regexp_replace(lotto_name, '^[[:space:]\\u00a0\\u200b-\\u200d\\ufeff]+|[[:space:]\\u00a0\\u200b-\\u200d\\ufeff]+$', '', 'g'), "
    "draw_date = regexp_replace(draw_date, '^[[:space:]\\u00a0\\u200b-\\u200d\\ufeff]+|[[:space:]\\u00a0\\u200b-\\u200d\\ufeff]+$', '', 'g') "
    "WHERE lotto_name ~ '^[[:space:]\\u00a0\\u200b-\\u200d\\ufeff]|[[:space:]\\u00a0\\u200b-\\u200d\\ufeff]$' "
    "OR draw_date ~ '^[[:space:]\\u00a0\\u200b-\\u200d\\ufeff]|[[:space:]\\u00a0\\u200b-\\u200d\\ufeff]$'",
]


def run_migrations():
    conn = psycopg2.connect(DB_URI)
    try:
        for sql in MIGRATIONS:
            try:
                conn.cursor().execute(sql)
                conn.commit()
            except Exception as e:
                conn.rollback()
                print("migration skipped:", sql[:70].replace("\n", " "), "->", str(e).splitlines()[0])
        _seed_admin(conn)
    finally:
        conn.close()


def _seed_admin(conn):
    u, p = os.environ.get("ADMIN_USERNAME"), os.environ.get("ADMIN_PASSWORD")
    if not (u and p):
        return
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM Users")
        if c.fetchone()[0] == 0:
            c.execute("INSERT INTO Users (username, password, role, parent_user) VALUES (%s,%s,'Admin',NULL)",
                      (u, store_password(p)))
            conn.commit()
            print("สร้างแอดมินเริ่มต้นแล้ว:", u)
    except Exception as e:
        conn.rollback()
        print("seed admin failed:", e)


# ============================================================ ควบคุมความเสี่ยง (วิเคราะห์ยอดซื้อรายเลข แบบเรียลไทม์)

def risk_options(c):
    c.execute("SELECT id, lotto_name, draw_date, status FROM LotteryCampaigns ORDER BY (status='Active') DESC, id DESC LIMIT 60")
    return [{"value": f"c:{r[0]}", "label": f"{clean_name(r[1])} งวด {clean_name(r[2])}" + ("" if r[3] == "Active" else " (ปิดแล้ว)")}
            for r in c.fetchall()]


def risk_data(c, root, f="", show_all=False):
    """วิเคราะห์ความเสี่ยงของงวดหนึ่ง: ถ้าเลขนั้นออก จะต้องจ่ายเท่าไร เทียบกับยอดสุทธิที่รับมา
    ขอบเขต: แอดมินเห็นทั้งระบบ / ผู้ใช้อื่นเห็นเฉพาะยอดของตัวเองและสายงานใต้ตัวเอง
    หมายเหตุ: ผลบน (3 หลัก) และผลล่าง (2 หลัก) ออกแยกกัน จึงรวมกรณีเลวร้ายสุดของสองฝั่ง"""
    me = get_user(c, root)
    if not me:
        return None
    if not (f or "").startswith("c:"):
        opts = risk_options(c)
        f = opts[0]["value"] if opts else ""
    camp = get_campaign(c, int(f[2:])) if f.startswith("c:") and f[2:].isdigit() else None
    if not camp:
        return {"error": "ยังไม่มีงวดหวย", "build": BUILD, "updated": get_thai_time().strftime("%d/%m/%Y %H:%M:%S")}
    where, wargs = _sales_filter(c, f)
    if me["role"] != "Admin":
        where += " AND username = ANY(%s)"
        wargs = (*wargs, get_subtree(c, me["username"]))
    c.execute(f"SELECT num, type, COALESCE(SUM(amount),0), COALESCE(SUM(amount*payout_rate),0), COALESCE(SUM(net),0) "
              f"FROM Transactions WHERE 1=1{where} GROUP BY num, type", wargs)
    rows = c.fetchall()
    half = {n for n, st in get_blocked_map(c, camp["lotto_name"], camp["draw_date"]).items() if st == "จ่ายครึ่ง"}

    items, total_amt, total_net = [], 0.0, 0.0
    # pay = ยอดจ่ายถ้าถูก, amt = ยอดซื้อ  (แยกตามประเภท)
    P = {t: {} for t in ("3ตัวตรง", "2ตัวบน", "2ตัวล่าง", "วิ่งบน", "วิ่งล่าง")}
    A = {t: {} for t in P}
    tod_p, tod_a, tod_pt, tod_at = {}, {}, {}, {}
    for num, t, amt, pay, net in rows:
        n, t = str(num).strip(), str(t).strip()
        amt, pay, net = float(amt), float(pay), float(net)
        is_half = n in half
        if is_half:
            pay /= 2.0
        total_amt += amt
        total_net += net
        items.append({"num": n, "type": t, "amount": amt, "pay": pay, "half": is_half})
        if t == "3ตัวโต๊ด":
            k = "".join(sorted(n))
            tod_p.setdefault(k, {})[n] = tod_p.setdefault(k, {}).get(n, 0) + pay
            tod_a.setdefault(k, {})[n] = tod_a.setdefault(k, {}).get(n, 0) + amt
            tod_pt[k] = tod_pt.get(k, 0) + pay
            tod_at[k] = tod_at.get(k, 0) + amt
        elif t in P:
            P[t][n] = P[t].get(n, 0) + pay
            A[t][n] = A[t].get(n, 0) + amt

    tops = []
    for i in range(1000):
        r = f"{i:03d}"
        k = "".join(sorted(r))
        ds = set(r)
        s3, p3 = A["3ตัวตรง"].get(r, 0), P["3ตัวตรง"].get(r, 0)
        stod, ptod = tod_at.get(k, 0) - tod_a.get(k, {}).get(r, 0), tod_pt.get(k, 0) - tod_p.get(k, {}).get(r, 0)
        s2, p2 = A["2ตัวบน"].get(r[-2:], 0), P["2ตัวบน"].get(r[-2:], 0)
        srun, prun = sum(A["วิ่งบน"].get(d, 0) for d in ds), sum(P["วิ่งบน"].get(d, 0) for d in ds)
        pay = p3 + ptod + p2 + prun
        stake = s3 + stod + s2 + srun
        if pay > 0 or stake > 0 or show_all:
            tops.append({"num": r, "s3": s3, "stod": stod, "s2": s2, "srun": srun, "stake": stake, "pay": pay})
    bots = []
    for i in range(100):
        r = f"{i:02d}"
        ds = set(r)
        s2, p2 = A["2ตัวล่าง"].get(r, 0), P["2ตัวล่าง"].get(r, 0)
        srun, prun = sum(A["วิ่งล่าง"].get(d, 0) for d in ds), sum(P["วิ่งล่าง"].get(d, 0) for d in ds)
        pay, stake = p2 + prun, s2 + srun
        if pay > 0 or stake > 0 or show_all:
            bots.append({"num": r, "s2": s2, "srun": srun, "stake": stake, "pay": pay})
    worst_top = max((x["pay"] for x in tops), default=0.0)
    worst_bot = max((x["pay"] for x in bots), default=0.0)
    items.sort(key=lambda x: (x["num"], x["type"]))
    for lst in (tops, bots, items):
        for x in lst:
            x["level"] = ("high" if x["pay"] > total_net else "mid" if x["pay"] > total_net * 0.5 else "low") if total_net > 0 else \
                         ("high" if x["pay"] > 0 else "low")
    return {"campaign": f"{camp['lotto_name']} งวด {camp['draw_date']}", "value": f, "scope": "ทั้งระบบ" if me["role"] == "Admin" else "สายงานของคุณ",
            "total_amount": total_amt, "total_net": total_net, "worst_top": worst_top, "worst_bot": worst_bot,
            "worst_total": worst_top + worst_bot, "worst_profit": total_net - worst_top - worst_bot,
            "tops": tops, "bots": bots, "items": items[:3000], "count": len(items),
            "build": BUILD, "updated": get_thai_time().strftime("%d/%m/%Y %H:%M:%S")}


_RISK_HTML = """
<style>
.rk-wrap{max-width:1300px;margin:0 auto}
.rk-card{background:#fff;border:1px solid #dee2e6;border-radius:8px;padding:12px;text-align:center}
.rk-card h6{color:#6c757d;font-size:.8rem;margin:0}.rk-card .v{font-size:1.4rem;font-weight:800}
.rk-table th{background:#212529;color:#fff;text-align:center;white-space:nowrap;position:sticky;top:0}.rk-table td{text-align:center;font-variant-numeric:tabular-nums}
.rk-table td.big{font-size:1.1rem;font-weight:800;letter-spacing:1px}
.rk-scroll{max-height:560px;overflow:auto;border:1px solid #dee2e6}
.rk-high{background:#f8d7da}.rk-mid{background:#fff3cd}.rk-over{outline:3px solid #dc3545;outline-offset:-3px}
.rk-live{display:inline-block;width:10px;height:10px;border-radius:50%;background:#198754;margin-right:6px;animation:rkp 1.2s infinite}
@keyframes rkp{50%{opacity:.25}}
</style>
<div class="rk-wrap">
  <div class="d-flex flex-wrap gap-2 align-items-center mb-2">
    <label class="fw-bold">งวด:</label>
    <select id="rk-f" class="form-select form-select-sm" style="max-width:320px">
      {% for o in options %}<option value="{{ o.value }}">{{ o.label }}</option>{% endfor %}
    </select>
    <label class="fw-bold ms-2">เรียงตาม:</label>
    <select id="rk-sort" class="form-select form-select-sm" style="max-width:240px">
      <option value="num">ลำดับเลข (น้อย → มาก)</option>
      <option value="stake">ยอดซื้อ (มาก → น้อย)</option>
      <option value="pay">จ่ายถ้าออก (มาก → น้อย)</option>
    </select>
    <label class="small ms-2">เพดานจ่ายต่อเลข (บาท): <input type="number" id="rk-limit" class="form-control form-control-sm d-inline-block" style="width:120px" min="0" step="1000" placeholder="ไม่กำหนด"></label>
  </div>
  <div class="d-flex flex-wrap gap-3 align-items-center mb-3">
    <label class="small"><input type="checkbox" id="rk-all"> แสดงเลขที่ยังไม่มียอดด้วย</label>
    <label class="small"><input type="checkbox" id="rk-auto" checked> รีเฟรชทุก 5 วินาที</label>
    <button class="btn btn-sm btn-outline-primary" id="rk-now" type="button">🔄 รีเฟรช</button>
    <span class="small text-muted"><span class="rk-live"></span><span id="rk-upd">กำลังโหลด...</span></span>
  </div>
  <div id="rk-alert"></div>
  <div class="row g-2 mb-3" id="rk-cards"></div>
  <div class="alert alert-info py-1 small">💡 "ยอดซื้อ" = เงินของรายการที่จะถูกรางวัลถ้าเลขนั้นออก · "จ่ายถ้าออก" ใช้อัตราจ่ายตอนซื้อ (เลขจ่ายครึ่งหารสอง) · 🔴 จ่ายมากกว่ายอดสุทธิที่รับ · 🟠 เกินครึ่งของยอดสุทธิ · ผลบนและผลล่างออกแยกกัน · {{ scope_note }}</div>
  <ul class="nav nav-tabs mb-2" id="rk-tabs">
    <li class="nav-item"><button class="nav-link active" type="button" data-t="top">🎯 เลขบน 3 ตัว</button></li>
    <li class="nav-item"><button class="nav-link" type="button" data-t="bot">🎯 เลขล่าง 2 ตัว</button></li>
    <li class="nav-item"><button class="nav-link" type="button" data-t="items">🔥 แยกประเภทการซื้อ</button></li>
  </ul>
  <div class="rk-scroll bg-white">
  <table class="table table-sm table-bordered rk-table mb-0"><thead id="rk-head"></thead><tbody id="rk-body"></tbody></table>
  </div>
</div>
<script>
(function(){
var URL0="{{ data_url }}",sel=document.getElementById('rk-f'),lim=document.getElementById('rk-limit'),srt=document.getElementById('rk-sort'),busy=false,tab='top',D=null;
try{lim.value=localStorage.getItem('rk-limit')||'';var sv=localStorage.getItem('rk-sort');if(sv)srt.value=sv;}catch(e){}
function nf(v){return Number(v).toLocaleString('th-TH',{minimumFractionDigits:2,maximumFractionDigits:2});}
function mk(t,c,x){var n=document.createElement(t);if(c)n.className=c;if(x!==undefined)n.textContent=x;return n;}
function limit(){var v=parseFloat(lim.value);return isNaN(v)||v<=0?null:v;}
function icon(l){return l==='high'?'🔴':l==='mid'?'🟠':'🟢';}
function load(){if(busy)return;busy=true;
 fetch(URL0+(URL0.indexOf('?')<0?'?':'&')+'f='+encodeURIComponent(sel.value)+'&all='+(document.getElementById('rk-all').checked?1:0),{credentials:'same-origin'}).then(function(r){if(!r.ok)throw new Error(r.status);return r.json();})
 .then(function(d){busy=false;D=d;draw();}).catch(function(){busy=false;document.getElementById('rk-upd').textContent='โหลดไม่สำเร็จ (จะลองใหม่)';});}
function card(t,v,cls){var c=mk('div','col-6 col-md-3'),b=mk('div','rk-card');b.appendChild(mk('h6','',t));b.appendChild(mk('div','v '+(cls||''),v));c.appendChild(b);return c;}
var COLS={top:[['เลข','num'],['3ตรง','s3'],['โต๊ด','stod'],['2บน','s2'],['วิ่งบน','srun'],['ยอดซื้อรวม','stake'],['จ่ายถ้าออก','pay'],['เทียบยอดสุทธิ','cmp']],
 bot:[['เลข','num'],['2ล่าง','s2'],['วิ่งล่าง','srun'],['ยอดซื้อรวม','stake'],['จ่ายถ้าออก','pay'],['เทียบยอดสุทธิ','cmp']],
 items:[['เลข','num'],['ประเภท','type'],['ยอดซื้อ','amount'],['จ่ายถ้าถูก','pay'],['เทียบยอดสุทธิ','cmp']]};
function sorted(list){var k=srt.value,a=list.slice();
 if(k==='num')a.sort(function(x,y){return x.num<y.num?-1:x.num>y.num?1:(x.type||'')<(y.type||'')?-1:1;});
 else{var f=(tab==='items')?(k==='stake'?'amount':'pay'):k;a.sort(function(x,y){return (y[f]-x[f])||(x.num<y.num?-1:1);});}
 return a;}
function draw(){var d=D;if(!d)return;
 if(d.error){document.getElementById('rk-upd').textContent=d.error;return;}
 if(sel.value!==d.value){sel.value=d.value;}
 var cards=document.getElementById('rk-cards');cards.textContent='';
 cards.appendChild(card('ยอดซื้อรวม',nf(d.total_amount)));cards.appendChild(card('ยอดสุทธิที่รับ',nf(d.total_net)));
 cards.appendChild(card('จ่ายสูงสุดถ้าเลวร้ายสุด',nf(d.worst_total),'text-danger'));
 cards.appendChild(card('กำไร/ขาดทุน กรณีเลวร้ายสุด',nf(d.worst_profit),d.worst_profit<0?'text-danger':'text-success'));
 var L=limit(),al=document.getElementById('rk-alert');al.textContent='';
 var over=d.tops.concat(d.bots).filter(function(x){return L&&x.pay>L;});
 if(d.worst_profit<0||over.length){al.appendChild(mk('div','alert alert-danger fw-bold py-2','⚠️ '+(d.worst_profit<0?'กรณีเลวร้ายสุดจะขาดทุน '+nf(-d.worst_profit)+' บาท ':'')+(over.length?'· มี '+over.length+' เลขที่จ่ายเกินเพดานที่ตั้งไว้ — พิจารณาอั้น/จ่ายครึ่ง':'')));}
 var cols=COLS[tab],head=document.getElementById('rk-head'),body=document.getElementById('rk-body');
 head.textContent='';var hr=mk('tr');cols.forEach(function(c){hr.appendChild(mk('th','',c[0]));});head.appendChild(hr);
 body.textContent='';var list=sorted(tab==='top'?d.tops:tab==='bot'?d.bots:d.items);
 list.forEach(function(x){var tr=mk('tr','rk-'+x.level+(L&&x.pay>L?' rk-over':''));
  cols.forEach(function(c){var k=c[1],td;
   if(k==='num')td=mk('td','big',x.num);else if(k==='type')td=mk('td','',x.type+(x.half?' (ครึ่ง)':''));
   else if(k==='cmp')td=mk('td','',icon(x.level)+' '+nf(d.total_net-x.pay));
   else td=mk('td','',x[k]?nf(x[k]):'-');
   tr.appendChild(td);});body.appendChild(tr);});
 if(!list.length){var tr=mk('tr'),td=mk('td','text-muted py-3','ยังไม่มีข้อมูล');td.colSpan=cols.length;tr.appendChild(td);body.appendChild(tr);}
 document.getElementById('rk-upd').textContent=d.campaign+' · '+d.scope+' · '+list.length+' รายการ · อัปเดต '+d.updated+' · รุ่น '+d.build;}
document.querySelectorAll('#rk-tabs button').forEach(function(b){b.onclick=function(){tab=b.getAttribute('data-t');document.querySelectorAll('#rk-tabs button').forEach(function(x){x.classList.toggle('active',x===b);});draw();};});
srt.onchange=function(){try{localStorage.setItem('rk-sort',srt.value);}catch(e){}draw();};
sel.onchange=load;document.getElementById('rk-all').onchange=load;lim.onchange=function(){try{localStorage.setItem('rk-limit',lim.value);}catch(e){}draw();};
document.getElementById('rk-now').onclick=load;
setInterval(function(){if(document.getElementById('rk-auto').checked&&!document.hidden)load();},5000);load();
})();
</script>
"""


def render_risk(c, data_url, scope_note=""):
    return _Jinja(_RISK_HTML, autoescape=True).render(options=risk_options(c), data_url=data_url, scope_note=scope_note)


# ============================================================ ตรวจสอบรายการซื้อ (กรองตามงวด / ผู้ซื้อ / เลข)

def audit_options(c, me):
    """ตัวเลือกงวดและผู้ซื้อ (ลูกค้า + ผู้ใช้ใต้สายงาน) ตามขอบเขตของผู้ดู"""
    camps = [{"value": o["value"][2:], "label": o["label"]} for o in risk_options(c)]
    if me["role"] == "Admin":
        c.execute("SELECT id, name FROM Customers ORDER BY name LIMIT 1000")
        cust = c.fetchall()
        c.execute("SELECT id, username FROM Users ORDER BY username LIMIT 1000")
        users = c.fetchall()
    else:
        sub = get_subtree(c, me["username"])
        c.execute("SELECT id, name FROM Customers WHERE owner_username = ANY(%s) ORDER BY name LIMIT 1000", (sub,))
        cust = c.fetchall()
        c.execute("SELECT id, username FROM Users WHERE username = ANY(%s) ORDER BY username LIMIT 1000", (sub,))
        users = c.fetchall()
    buyers = [{"value": f"Customer:{i}", "label": f"👤 ลูกค้า: {n}"} for i, n in cust] + \
             [{"value": f"User:{i}", "label": f"🧑‍💼 ผู้ใช้/สายงาน: {n}"} for i, n in users]
    return camps, buyers


def audit_data(c, me, camp_id, buyer="", num="", limit=3000):
    where, wargs = _sales_filter(c, f"c:{int(camp_id)}")
    if me["role"] != "Admin":
        where += " AND username = ANY(%s)"
        wargs = (*wargs, get_subtree(c, me["username"]))
    if buyer:
        try:
            kind, bid = buyer.split(":", 1)
            bid = int(bid)
        except ValueError:
            kind, bid = "", 0
        if kind == "Customer":
            where += " AND customer_type='Customer' AND customer_id=%s"
            wargs = (*wargs, bid)
        elif kind == "User":
            c.execute("SELECT username FROM Users WHERE id=%s", (bid,))
            r = c.fetchone()
            sub = get_subtree(c, r[0]) if r else []
            where += " AND ((customer_type='User' AND customer_id=%s) OR username = ANY(%s))"
            wargs = (*wargs, bid, sub)
    num = (num or "").strip()
    if num:
        where += " AND num = %s"
        wargs = (*wargs, num)
    c.execute(f"SELECT COALESCE(SUM(amount),0), COALESCE(SUM(discount),0), COALESCE(SUM(net),0), COUNT(*), COUNT(DISTINCT bill_no) "
              f"FROM Transactions WHERE 1=1{where}", wargs)
    t = c.fetchone()
    c.execute(f"SELECT timestamp, bill_no, username, customer_name, customer_type, type, num, amount, discount, net, payout_rate "
              f"FROM Transactions WHERE 1=1{where} ORDER BY id DESC LIMIT {int(limit)}", wargs)
    rows = c.fetchall()
    return {"rows": rows, "amount": float(t[0]), "discount": float(t[1]), "net": float(t[2]), "count": t[3], "bills": t[4],
            "truncated": t[3] > len(rows)}


_AUDIT_HTML = """
<div class="card shadow p-3">
  <h3 class="text-primary fw-bold mb-3">{{ title }}</h3>
  <form method="GET" action="{{ action }}" class="row g-2 align-items-end mb-3">
    {% for k, v in hidden.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
    <div class="col-md-4"><label class="form-label small fw-bold">งวด</label>
      <select name="camp" class="form-select form-select-sm">{% for o in camps %}<option value="{{ o.value }}" {{ 'selected' if o.value == camp|string }}>{{ o.label }}</option>{% endfor %}</select></div>
    <div class="col-md-4"><label class="form-label small fw-bold">ผู้ซื้อ (ลูกค้า / ผู้ใช้ใต้สายงาน)</label>
      <select name="buyer" class="form-select form-select-sm"><option value="">— ทั้งหมด —</option>{% for o in buyers %}<option value="{{ o.value }}" {{ 'selected' if o.value == buyer }}>{{ o.label }}</option>{% endfor %}</select></div>
    <div class="col-md-2"><label class="form-label small fw-bold">เลข (ไม่บังคับ)</label><input type="text" name="num" value="{{ num }}" class="form-control form-control-sm" maxlength="3"></div>
    <div class="col-md-2"><button class="btn btn-primary btn-sm w-100 fw-bold" type="submit">🔍 แสดงข้อมูล</button></div>
  </form>
  <div class="row g-2 mb-3 text-center">
    <div class="col"><div class="border rounded p-2 bg-light"><div class="small text-muted">บิล</div><b>{{ d.bills }}</b></div></div>
    <div class="col"><div class="border rounded p-2 bg-light"><div class="small text-muted">รายการ</div><b>{{ d.count }}</b></div></div>
    <div class="col"><div class="border rounded p-2 bg-light"><div class="small text-muted">ยอดซื้อ</div><b>{{ "{:,.2f}".format(d.amount) }}</b></div></div>
    <div class="col"><div class="border rounded p-2 bg-light"><div class="small text-muted">ส่วนลด</div><b class="text-danger">{{ "{:,.2f}".format(d.discount) }}</b></div></div>
    <div class="col"><div class="border rounded p-2 bg-light"><div class="small text-muted">ยอดสุทธิ</div><b class="text-success">{{ "{:,.2f}".format(d.net) }}</b></div></div>
  </div>
  {% if d.truncated %}<div class="alert alert-warning py-1 small">แสดง {{ d.rows|length }} รายการล่าสุดจากทั้งหมด {{ d.count }} รายการ — เลือกผู้ซื้อหรือเลขเพื่อดูให้แคบลง (ยอดรวมด้านบนนับครบทั้งหมด)</div>{% endif %}
  <div class="table-responsive" style="max-height:640px">
    <table class="table table-striped table-bordered table-sm text-center align-middle">
      <thead class="table-dark" style="position:sticky;top:0"><tr><th>เวลา</th><th>เลขที่บิล</th><th>ผู้บันทึก</th><th>ผู้ซื้อ</th><th>ประเภท</th><th>เลข</th><th>ยอดซื้อ</th><th>ส่วนลด</th><th>สุทธิ</th><th>อัตราจ่าย</th></tr></thead>
      <tbody>
      {% for r in d.rows %}
        <tr><td><small>{{ r[0] }}</small></td><td><code>{{ r[1] }}</code></td><td><span class="badge bg-secondary">{{ r[2] }}</span></td>
        <td><b>{{ r[3] }}</b> <span class="badge {{ 'bg-primary' if r[4] == 'User' else 'bg-info text-dark' }}">{{ 'สายงาน' if r[4] == 'User' else 'ลูกค้า' }}</span></td>
        <td>{{ r[5] }}</td><td><b class="text-primary">{{ r[6] }}</b></td>
        <td class="text-end">{{ "{:,.2f}".format(r[7] | float) }}</td><td class="text-end text-danger">{{ "{:,.2f}".format(r[8] | float) }}</td>
        <td class="text-end text-success fw-bold">{{ "{:,.2f}".format(r[9] | float) }}</td><td><span class="badge bg-success">{{ r[10] }}</span></td></tr>
      {% else %}<tr><td colspan="10" class="text-muted py-3">ไม่พบรายการตามเงื่อนไขที่เลือก</td></tr>{% endfor %}
      </tbody>
    </table>
  </div>
</div>
"""


def render_audit(c, me, action, hidden, title, camp="", buyer="", num="", draw=""):
    camps, buyers = audit_options(c, me)
    ids = [o["value"] for o in camps]
    if camp not in ids:
        camp = ""
        if draw:   # รองรับลิงก์เดิมที่ส่ง draw = "ชื่อหวย งวด วันที่"
            for o in camps:
                if o["label"].replace(" (ปิดแล้ว)", "") == draw.strip():
                    camp = o["value"]
                    break
        if not camp and ids:
            camp = ids[0]
    d = audit_data(c, me, camp, buyer, num) if camp else {"rows": [], "amount": 0.0, "discount": 0.0, "net": 0.0, "count": 0, "bills": 0, "truncated": False}
    return _Jinja(_AUDIT_HTML, autoescape=True).render(action=action, hidden=hidden, title=title, camps=camps, buyers=buyers,
                                                       camp=camp, buyer=buyer, num=num, d=d)


# ============================================================ ยกเลิกบิล

_TX_COPY = "draw_date, timestamp, username, customer_id, customer_name, customer_type, bill_no, num, type, amount, status, discount, net, payout_rate, lotto_name"


def _result_recorded(c, draw_date):
    c.execute("SELECT 1 FROM DrawResults WHERE (draw_date=%s OR draw_date ILIKE %s) AND COALESCE(prize_1,'')<>'' LIMIT 1",
              (draw_date, f"%{like_escape(draw_date)}%"))
    return bool(c.fetchone())


def _camp_of_tx(c, draw_date, lotto_name):
    c.execute("SELECT id FROM LotteryCampaigns WHERE draw_date=%s OR draw_date ILIKE %s ORDER BY id DESC", (draw_date, f"%{like_escape(draw_date)}%"))
    ids = [r[0] for r in c.fetchall()]
    best = None
    for i in ids:
        camp = get_campaign(c, i)
        if camp and (not lotto_name or _name_key(camp["lotto_name"]) == _name_key(lotto_name)):
            return camp
        best = best or camp
    return best


def bill_cancel_state(c, me, camp, bill_user):
    """(ยกเลิกได้ไหม, เหตุผลถ้าไม่ได้)"""
    if me["role"] != "Admin" and (bill_user or "").lower() != me["username"].lower():
        return False, "ยกเลิกได้เฉพาะบิลที่คุณคีย์เอง"
    if camp and _result_recorded(c, camp["draw_date"]):
        return False, "งวดนี้ออกผลรางวัลแล้ว ยกเลิกไม่ได้"
    if me["role"] != "Admin":
        if not camp:
            return False, "ไม่พบงวดของบิลนี้"
        ok, why = campaign_open(camp)
        if not ok:
            return False, "ปิดรับงวดแล้ว ยกเลิกไม่ได้ (ติดต่อแอดมิน)"
    return True, ""


def cancel_bill(c, me, bill_no, reason=""):
    """ยกเลิกบิล: ย้ายรายการไปเก็บในตาราง CancelledTransactions แล้วลบออกจาก Transactions
    (รายงาน/ยอดขายสด/ความเสี่ยง/ผลรางวัล จึงไม่นับบิลนี้อีก)  คืน (ok, ข้อความ)"""
    bill_no = (bill_no or "").strip()
    if not bill_no:
        return False, "ไม่ระบุเลขที่บิล"
    c.execute("SELECT id, draw_date, lotto_name, username FROM Transactions WHERE bill_no=%s FOR UPDATE", (bill_no,))
    rows = c.fetchall()
    if not rows:
        return False, "ไม่พบบิลนี้ (อาจถูกยกเลิกไปแล้ว)"
    draw_date, lotto_name, owner = rows[0][1], rows[0][2], rows[0][3]
    camp = _camp_of_tx(c, draw_date, lotto_name)
    ok, why = bill_cancel_state(c, me, camp, owner)
    if not ok:
        return False, why
    now = get_thai_time().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(f"INSERT INTO CancelledTransactions (orig_id, {_TX_COPY}, cancelled_by, cancelled_at, reason) "
              f"SELECT id, {_TX_COPY}, %s, %s, %s FROM Transactions WHERE bill_no=%s AND draw_date=%s",
              (me["username"], now, (reason or "").strip()[:200], bill_no, draw_date))
    c.execute("DELETE FROM Transactions WHERE bill_no=%s AND draw_date=%s", (bill_no, draw_date))
    credit_refund(c, bill_no, me["username"])
    return True, f"ยกเลิกบิล {bill_no} เรียบร้อย ({len(rows)} รายการ)"


def list_bills(c, me, camp_id, limit=200):
    where, wargs = _sales_filter(c, f"c:{int(camp_id)}")
    if me["role"] != "Admin":
        where += " AND LOWER(username)=LOWER(%s)"
        wargs = (*wargs, me["username"])
    c.execute(f"SELECT bill_no, MAX(timestamp), MAX(username), MAX(customer_name), MAX(customer_type), COUNT(*), "
              f"COALESCE(SUM(amount),0), COALESCE(SUM(net),0) FROM Transactions WHERE bill_no IS NOT NULL{where} "
              f"GROUP BY bill_no ORDER BY MAX(id) DESC LIMIT {int(limit)}", wargs)
    return c.fetchall()


_CANCEL_HTML = """
<div class="card shadow p-3">
  <h3 class="text-danger fw-bold mb-1">🗑️ ยกเลิกบิล</h3>
  <div class="text-muted mb-2">{{ camp_label }} · {{ 'แอดมินยกเลิกได้ทุกบิลจนกว่าจะออกผล' if is_admin else 'ยกเลิกได้เฉพาะบิลที่คุณคีย์เอง ขณะที่งวดยังเปิดรับ' }}</div>
  {% if blocked_reason %}<div class="alert alert-warning py-2">{{ blocked_reason }}</div>{% endif %}
  <input type="text" id="cb-q" class="form-control form-control-sm mb-2" placeholder="🔍 ค้นหาเลขที่บิล / ชื่อผู้ซื้อ" style="max-width:320px">
  <div class="table-responsive" style="max-height:620px">
  <table class="table table-sm table-bordered table-striped text-center align-middle" id="cb-t">
    <thead class="table-dark" style="position:sticky;top:0"><tr><th>เวลา</th><th>เลขที่บิล</th><th>ผู้บันทึก</th><th>ผู้ซื้อ</th><th>รายการ</th><th>ยอดซื้อ</th><th>สุทธิ</th><th>จัดการ</th></tr></thead>
    <tbody>
    {% for b in bills %}
      <tr><td><small>{{ b.time }}</small></td><td><code>{{ b.bill_no }}</code></td><td>{{ b.user }}</td><td><b>{{ b.buyer }}</b></td>
      <td>{{ b.n }}</td><td class="text-end">{{ "{:,.2f}".format(b.amount) }}</td><td class="text-end">{{ "{:,.2f}".format(b.net) }}</td>
      <td>{% if b.can %}
        <form method="POST" action="{{ action }}" class="d-flex gap-1 justify-content-center" onsubmit="return confirm('ยืนยันยกเลิกบิล {{ b.bill_no }} ? การยกเลิกจะนำรายการทั้งบิลออกจากยอดขาย');">
          {% for k, v in hidden.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
          <input type="hidden" name="bill_no" value="{{ b.bill_no }}">
          <input type="text" name="reason" class="form-control form-control-sm" placeholder="เหตุผล (ไม่บังคับ)" style="width:150px" maxlength="200">
          <button class="btn btn-danger btn-sm fw-bold" type="submit">ยกเลิกบิล</button>
        </form>
      {% else %}<small class="text-muted">{{ b.why }}</small>{% endif %}</td></tr>
    {% else %}<tr><td colspan="8" class="text-muted py-3">ยังไม่มีบิลในงวดนี้</td></tr>{% endfor %}
    </tbody>
  </table></div>
</div>
<script>
document.getElementById('cb-q').oninput=function(){var q=this.value.toLowerCase();
 document.querySelectorAll('#cb-t tbody tr').forEach(function(r){r.style.display=r.textContent.toLowerCase().indexOf(q)<0?'none':'';});};
</script>
"""


def render_cancel_bills(c, me, camp, action, hidden):
    bills, blocked_reason = [], ""
    for r in list_bills(c, me, camp["id"]):
        ok, why = bill_cancel_state(c, me, camp, r[2])
        bills.append({"bill_no": r[0], "time": r[1], "user": r[2], "buyer": r[3], "n": r[5],
                      "amount": float(r[6]), "net": float(r[7]), "can": ok, "why": why})
    if bills and not any(b["can"] for b in bills):
        blocked_reason = bills[0]["why"]
    return _Jinja(_CANCEL_HTML, autoescape=True).render(bills=bills, action=action, hidden=hidden, is_admin=me["role"] == "Admin",
                                                        camp_label=f"{camp['lotto_name']} งวด {camp['draw_date']}", blocked_reason=blocked_reason)


# ============================================================ คีย์ด่วน (ต่อเนื่อง / วางโพย) + โพยร่างแบบ 6 คอลัมน์

TOP_TYPES = ("3ตัวตรง", "2ตัวบน", "วิ่งบน")
_AMT = r"\d+(?:\.\d+)?"


def parse_quick(text):
    """แปลงข้อความคีย์ด่วนเป็นรายการ [(เลข, ยอดบน, ยอดล่าง)]
    รูปแบบ:  เลข=บน*ล่าง   คั่นด้วย , หรือขึ้นบรรทัดใหม่   เลขหลายตัวยอดเท่ากัน:  14,41=10*10
    ใส่ 0 ในตำแหน่งที่ไม่ซื้อ  เช่น 456=0*50   (ใส่ยอดเดียว 123=100 = ซื้อฝั่งบนอย่างเดียว)
    คืน (entries, errors)"""
    s = (text or "").replace("＝", "=").replace("＊", "*").replace("×", "*")
    s = re.sub(r"(?<=\d)\s*[xX]\s*(?=\d)", "*", s)
    s = re.sub(r"\s*=\s*", "=", s)
    s = re.sub(r"\s*\*\s*", "*", s)
    entries, errors, pending = [], [], []
    for tok in [t for t in re.split(r"[,\s;]+", s) if t]:
        if "=" not in tok:
            pending.append(tok)
            continue
        left, right = tok.split("=", 1)
        if left:
            pending.append(left)
        m = re.fullmatch(rf"({_AMT})(?:\*({_AMT}))?", right)
        if not pending:
            errors.append(f"'{tok}' ไม่มีเลขที่จะซื้อ")
            continue
        if not m:
            errors.append(f"ยอดซื้อไม่ถูกต้อง: '{right}' (ต้องเป็น บน*ล่าง เช่น 10*20)")
            pending = []
            continue
        top, bot = float(m.group(1)), float(m.group(2) or 0)
        for n in pending:
            if not re.fullmatch(r"\d{1,3}", n):
                errors.append(f"เลขไม่ถูกต้อง: '{n}' (ต้องเป็นตัวเลข 1-3 หลัก)")
            elif top <= 0 and bot <= 0:
                errors.append(f"เลข {n} ไม่มียอดซื้อ (บนและล่างเป็น 0)")
            else:
                entries.append((n, top, bot))
        pending = []
    if pending:
        errors.append("เลขที่ไม่มียอดซื้อ (ลืมใส่ =ยอด): " + ", ".join(pending[:20]))
    return entries, errors


def make_draft_rows(rates, blocked, entries, username, t_type, t_id, camp, max_amount=1_000_000):
    """สร้างแถว TempDraft จาก [(เลข, บน, ล่าง)]  คืน (rows, rejected, invalid)"""
    rows, rejected, invalid = [], [], []
    for n, top, bot in entries:
        if not re.fullmatch(r"\d{1,3}", n) or not (0 <= top <= max_amount and 0 <= bot <= max_amount):
            invalid.append(n)
            continue
        st = blocked.get(n, "ปกติ")
        if st == "ปิดรับ":
            rejected.append(n)
            continue
        for amt, (ptype, pay_key, kind) in zip((top, bot), PLAYS[len(n)]):
            if amt <= 0:
                continue
            disc_amt = round(amt * disc_pct(rates, kind) / 100.0, 2)
            rows.append((username, str(t_id), t_type, n, amt, ptype, rates[pay_key], disc_amt, round(amt - disc_amt, 2),
                         st, camp["lotto_name"], camp["draw_date"]))
    return rows, rejected, invalid


def group_draft(drafts):
    """TempDraft (id,num,amt,status,type,payout_rate,discount,net) -> แถวต่อ 'เลข' (บน/3ตรง | ล่าง/โต๊ด)
    rate ที่แสดงเป็น 'อัตราจ่ายจริง' (เลขจ่ายครึ่งแสดงครึ่งหนึ่ง)"""
    order, g = [], {}
    for d in drafts:
        n = d[1]
        if n not in g:
            g[n] = {"num": n, "ids": [], "top": 0.0, "bot": 0.0, "top_rate": None, "bot_rate": None,
                    "disc": 0.0, "net": 0.0, "status": d[3] or "ปกติ"}
            order.append(n)
        r = g[n]
        r["ids"].append(d[0])
        slot = "top" if d[4] in TOP_TYPES else "bot"
        r[slot] += float(d[2] or 0)
        rate = float(d[5] or 0)
        r[slot + "_rate"] = rate / 2.0 if (d[3] or "ปกติ") != "ปกติ" else rate
        r["disc"] += float(d[6] or 0)
        r["net"] += float(d[7] or 0)
    rows = [g[n] for n in order]
    for r in rows:
        r["total"] = r["top"] + r["bot"]
        r["ids_csv"] = ",".join(str(i) for i in r["ids"])
    tot = {"top": sum(r["top"] for r in rows), "bot": sum(r["bot"] for r in rows),
           "amt": sum(r["total"] for r in rows), "disc": sum(r["disc"] for r in rows), "net": sum(r["net"] for r in rows)}
    return rows, tot


# ============================================================ ระบบเครดิต

def _acct_table(kind):
    return "Users" if kind == "User" else "Customers"


def credit_enabled(c, kind, tid):
    c.execute(f"SELECT COALESCE(credit_enabled, FALSE) FROM {_acct_table(kind)} WHERE id=%s", (tid,))
    r = c.fetchone()
    return bool(r and r[0])


def credit_balance(c, kind, tid):
    c.execute("SELECT COALESCE(SUM(delta),0) FROM CreditLedger WHERE target_type=%s AND target_id=%s", (kind, tid))
    return float(c.fetchone()[0] or 0)


def credit_account(c, t_type, t_id, me):
    """บัญชีเครดิตที่ต้องตัดเมื่อออกบิล: ผู้ซื้อ (ถ้าเปิดเครดิตไว้) ไม่เช่นนั้นผู้บันทึก (ตัวแทน) ถ้าเปิดเครดิตไว้ ไม่มีก็ไม่ตัด"""
    if credit_enabled(c, t_type, t_id):
        return (t_type, t_id)
    if me and credit_enabled(c, "User", me["id"]):
        return ("User", me["id"])
    return None


def _ledger(c, kind, tid, delta, ltype, bill_no, note, by):
    c.execute("INSERT INTO CreditLedger (target_type, target_id, delta, kind, bill_no, note, by_user, created_at) "
              "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
              (kind, tid, round(float(delta), 2), ltype, bill_no, (note or "")[:200], by, get_thai_time().strftime("%Y-%m-%d %H:%M:%S")))


def credit_charge(c, acct, amount, bill_no, by):
    """ตัดเครดิตตอนออกบิล (ล็อกแถวบัญชีกันตัดซ้อน)  คืน (ok, ข้อความ)"""
    kind, tid = acct
    c.execute(f"SELECT 1 FROM {_acct_table(kind)} WHERE id=%s FOR UPDATE", (tid,))
    bal = credit_balance(c, kind, tid)
    if bal + 1e-9 < amount:
        return False, f"เครดิตไม่พอ (คงเหลือ {bal:,.2f} บาท ต้องใช้ {amount:,.2f} บาท) กรุณาติดต่อแอดมินเพื่อเพิ่มเครดิต"
    _ledger(c, kind, tid, -amount, "purchase", bill_no, "ซื้อโพย", by)
    return True, ""


def credit_refund(c, bill_no, by):
    """คืนเครดิตเมื่อยกเลิกบิล (คืนครั้งเดียวต่อบิล)"""
    c.execute("SELECT target_type, target_id, SUM(delta) FROM CreditLedger WHERE bill_no=%s AND kind IN ('purchase','refund') "
              "GROUP BY target_type, target_id", (bill_no,))
    for kind, tid, net in c.fetchall():
        if float(net or 0) < 0:
            _ledger(c, kind, tid, -float(net), "refund", bill_no, "ยกเลิกบิล", by)


def _in_my_line(c, me, kind, tid):
    """บัญชีนี้อยู่ใต้สายงานของ me (ทุกชั้น, ไม่รวมตัวเอง) หรือไม่  ผู้ใช้=อยู่ใน subtree  ลูกค้า=เจ้าของอยู่ใน subtree"""
    names = {n.lower() for n in get_subtree(c, me["username"])}
    if kind == "User":
        c.execute("SELECT username FROM Users WHERE id=%s", (tid,))
        r = c.fetchone()
        return bool(r) and r[0].lower() in names and tid != me["id"]
    c.execute("SELECT owner_username FROM Customers WHERE id=%s", (tid,))
    r = c.fetchone()
    return bool(r) and (r[0] or "").lower() in names


def credit_adjust(c, me, target, op, amount=0.0, note=""):
    """จัดการเครดิต  target='User:5' | 'Customer:3'  คืน (ok, ข้อความ)
    แอดมิน: allocate(สร้างเครดิตใหม่)/deduct/clear/enable/disable ได้กับทุกบัญชี
    ผู้ใช้ทุกระดับ: transfer (แบ่งเครดิตของตัวเองให้ผู้ใช้/ลูกค้าใต้สายงานทุกชั้น ไม่เกินยอดคงเหลือของตัวเอง)
                  reclaim  (ดึงคืนจากใต้สายงาน ไม่เกินยอดคงเหลือของผู้ถูกดึง)"""
    is_admin = me["role"] == "Admin"
    try:
        kind, tid = target.split(":", 1)
        tid = int(tid)
        assert kind in ("User", "Customer")
    except (ValueError, AssertionError):
        return False, "ข้อมูลบัญชีไม่ถูกต้อง"
    name = get_target_name(c, kind, tid)
    if name is None:
        return False, "ไม่พบบัญชีนี้"
    if op in ("transfer", "reclaim"):
        if kind == "User" and tid == me["id"]:
            return False, "ไม่สามารถโอนให้ตัวเองได้"
        if not _in_my_line(c, me, kind, tid):
            return False, "โอน/ดึงเครดิตได้เฉพาะบัญชีที่อยู่ใต้สายงานของคุณเท่านั้น"
        amount = round(float(amount or 0), 2)
        if amount <= 0 or amount > 1e9:
            return False, "จำนวนเงินต้องมากกว่า 0"
        # ล็อกสองบัญชีตามลำดับคงที่ กันโอนสวนกันแล้วค้าง/ยอดเพี้ยน
        for k, i in sorted([("User", me["id"]), (kind, tid)]):
            c.execute(f"SELECT 1 FROM {_acct_table(k)} WHERE id=%s FOR UPDATE", (i,))
        my = ("User", me["id"])
        src, dst = (my, (kind, tid)) if op == "transfer" else ((kind, tid), my)
        have = credit_balance(c, *src)
        if have + 1e-9 < amount:
            who = "เครดิตคงเหลือของคุณ" if op == "transfer" else f"เครดิตคงเหลือของ {name} "
            return False, f"{who}ไม่พอ (คงเหลือ {have:,.2f} บาท ต้องการ {amount:,.2f} บาท)"
        out_k, in_k = ("transfer_out", "transfer_in") if op == "transfer" else ("reclaim_out", "reclaim_in")
        who_me = me["username"]
        _ledger(c, src[0], src[1], -amount, out_k, None, note or (f"โอนให้ {name}" if op == "transfer" else f"{who_me} ดึงคืน"), who_me)
        _ledger(c, dst[0], dst[1], amount, in_k, None, note or (f"รับจาก {who_me}" if op == "transfer" else f"ดึงคืนจาก {name}"), who_me)
        c.execute(f"UPDATE {_acct_table(dst[0])} SET credit_enabled=TRUE WHERE id=%s", (dst[1],))
        return True, (f"โอนเครดิต {amount:,.2f} ให้ {name} แล้ว (คงเหลือของคุณ {credit_balance(c, *my):,.2f})" if op == "transfer"
                      else f"ดึงเครดิตคืน {amount:,.2f} จาก {name} แล้ว (คงเหลือของคุณ {credit_balance(c, *my):,.2f})")
    if not is_admin:
        return False, "คำสั่งนี้สำหรับแอดมินเท่านั้น (ผู้ใช้ทั่วไปแบ่งเครดิตให้สายงานตัวเองได้)"
    if op in ("enable", "disable"):
        c.execute(f"UPDATE {_acct_table(kind)} SET credit_enabled=%s WHERE id=%s", (op == "enable", tid))
        return True, f"{'เปิด' if op == 'enable' else 'ปิด'}ระบบเครดิตของ {name} แล้ว"
    c.execute(f"SELECT 1 FROM {_acct_table(kind)} WHERE id=%s FOR UPDATE", (tid,))
    if op == "clear":
        bal = credit_balance(c, kind, tid)
        if abs(bal) < 0.005:
            return False, "ยอดเป็น 0 อยู่แล้ว"
        _ledger(c, kind, tid, -bal, "settle", None, note or "เคลียร์ยอด", me["username"])
        return True, f"เคลียร์ยอดของ {name} (ปรับ {-bal:+,.2f})"
    amount = float(amount or 0)
    if amount <= 0 or amount > 1e9:
        return False, "จำนวนเงินต้องมากกว่า 0"
    if op == "allocate":
        c.execute(f"UPDATE {_acct_table(kind)} SET credit_enabled=TRUE WHERE id=%s", (tid,))
        _ledger(c, kind, tid, amount, "allocate", None, note or "จัดสรรเครดิต", me["username"])
        return True, f"จัดสรรเครดิต {amount:,.2f} ให้ {name} แล้ว"
    if op == "deduct":
        _ledger(c, kind, tid, -amount, "adjust", None, note or "หัก/ปรับยอด", me["username"])
        return True, f"หักเครดิต {amount:,.2f} จาก {name} แล้ว"
    return False, "คำสั่งไม่ถูกต้อง"


_CREDIT_HTML = """
<div class="card shadow p-3">
  <h3 class="fw-bold text-primary mb-1">💳 ระบบเครดิต</h3>
  <div class="text-muted small mb-3">{% if is_admin %}แอดมินจัดสรรเครดิตให้ผู้ใช้/ตัวแทน/ลูกค้า — เมื่อออกบิลระบบจะตัดเครดิตของผู้ซื้อ (ถ้าผู้ซื้อไม่ได้เปิดเครดิต จะตัดจากเครดิตของผู้บันทึกที่เปิดเครดิตไว้) ถ้าไม่พอจะออกบิลไม่ได้ · ยกเลิกบิลจะคืนเครดิตให้อัตโนมัติ{% else %}คุณแบ่งเครดิต "ของตัวเอง" ให้ผู้ใช้/ลูกค้าใต้สายงานได้ทุกชั้น ภายใต้ยอดคงเหลือของคุณเท่านั้น (เครดิตตั้งต้นมาจากแอดมิน) · ดึงคืนได้ไม่เกินยอดคงเหลือของผู้ถูกดึง{% endif %}</div>
  {% if not is_admin %}<div class="alert alert-success d-flex justify-content-between align-items-center py-2"><span>💳 เครดิตคงเหลือของคุณ ({{ me_name }})</span><b class="fs-4">{{ "{:,.2f}".format(my_balance) }} บาท</b></div>{% endif %}
  <input type="text" id="cr-q" class="form-control form-control-sm mb-2" placeholder="🔍 ค้นหาชื่อ" style="max-width:280px">
  <div class="table-responsive">
  <table class="table table-sm table-bordered align-middle text-center" id="cr-t">
    <thead class="table-dark"><tr><th>ชื่อ</th><th>ประเภท</th><th>ระบบเครดิต</th><th>คงเหลือ</th><th>ซื้อไปแล้ว</th><th style="min-width:{{ 420 if is_admin else 330 }}px">จัดการ</th></tr></thead>
    <tbody>
    {% for a in accts %}
      <tr><td class="text-start"><b>{{ a.name }}</b></td><td>{{ 'ผู้ใช้/ตัวแทน' if a.kind == 'User' else 'ลูกค้า' }}</td>
      <td>{% if a.enabled %}<span class="badge bg-success">เปิด</span>{% else %}<span class="badge bg-secondary">ปิด</span>{% endif %}</td>
      <td class="fw-bold {{ 'text-danger' if a.balance < 0 else 'text-success' }}">{{ "{:,.2f}".format(a.balance) }}</td>
      <td>{{ "{:,.2f}".format(a.used) }}</td>
      {% if is_admin %}<td>
        <form method="POST" action="{{ action }}" class="d-flex flex-wrap gap-1 justify-content-center">
          {% for k, v in hidden.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
          <input type="hidden" name="target" value="{{ a.kind }}:{{ a.id }}">
          <input type="number" name="amount" step="0.01" min="0" class="form-control form-control-sm" placeholder="จำนวนเงิน" style="width:110px">
          <input type="text" name="note" class="form-control form-control-sm" placeholder="หมายเหตุ" style="width:120px" maxlength="200">
          <button name="op" value="allocate" class="btn btn-success btn-sm">➕ จัดสรร/เติม</button>
          <button name="op" value="deduct" class="btn btn-warning btn-sm">➖ หัก</button>
          <button name="op" value="clear" class="btn btn-outline-dark btn-sm" onclick="return confirm('เคลียร์ยอดของ {{ a.name }} ให้เป็น 0 ?')">เคลียร์ยอด</button>
          {% if a.enabled %}<button name="op" value="disable" class="btn btn-outline-secondary btn-sm">ปิดเครดิต</button>
          {% else %}<button name="op" value="enable" class="btn btn-outline-primary btn-sm">เปิดเครดิต</button>{% endif %}
        </form></td>
      {% else %}<td>
        <form method="POST" action="{{ action }}" class="d-flex flex-wrap gap-1 justify-content-center">
          {% for k, v in hidden.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
          <input type="hidden" name="target" value="{{ a.kind }}:{{ a.id }}">
          <input type="number" name="amount" step="0.01" min="0.01" class="form-control form-control-sm" placeholder="จำนวนเงิน" style="width:110px" required>
          <input type="text" name="note" class="form-control form-control-sm" placeholder="หมายเหตุ" style="width:110px" maxlength="200">
          <button name="op" value="transfer" class="btn btn-success btn-sm">➡️ โอนให้</button>
          <button name="op" value="reclaim" class="btn btn-outline-warning btn-sm" onclick="return confirm('ดึงเครดิตคืนจาก {{ a.name }} ?')">⬅️ ดึงคืน</button>
        </form></td>{% endif %}</tr>
    {% else %}<tr><td colspan="6" class="text-muted py-3">{{ 'ไม่มีบัญชี' if is_admin else 'ยังไม่มีผู้ใช้/ลูกค้าใต้สายงานของคุณ' }}</td></tr>{% endfor %}
    </tbody>
  </table></div>
  <h6 class="fw-bold mt-3">🧾 รายการล่าสุด</h6>
  <div class="table-responsive" style="max-height:320px"><table class="table table-sm table-striped table-bordered text-center" style="font-size:.8rem">
    <thead class="table-light"><tr><th>เวลา</th><th>บัญชี</th><th>ประเภท</th><th>จำนวน</th><th>บิล</th><th>หมายเหตุ</th><th>โดย</th></tr></thead><tbody>
    {% for l in ledger %}<tr><td>{{ l[0] }}</td><td>{{ l[1] }}</td><td>{{ l[2] }}</td><td class="{{ 'text-success' if l[3] > 0 else 'text-danger' }}">{{ "{:+,.2f}".format(l[3]) }}</td><td>{{ l[4] or '' }}</td><td>{{ l[5] or '' }}</td><td>{{ l[6] }}</td></tr>
    {% else %}<tr><td colspan="7" class="text-muted">ยังไม่มีรายการ</td></tr>{% endfor %}</tbody></table></div>
</div>
<script>document.getElementById('cr-q').oninput=function(){var q=this.value.toLowerCase();document.querySelectorAll('#cr-t tbody tr').forEach(function(r){r.style.display=r.textContent.toLowerCase().indexOf(q)<0?'none':'';});};</script>
"""

_KIND_TH = {"transfer_out": "โอนออก", "transfer_in": "รับโอน", "reclaim_out": "ถูกดึงคืน", "reclaim_in": "ดึงคืนเข้า", "allocate": "จัดสรร", "adjust": "หัก/ปรับ", "settle": "เคลียร์ยอด", "purchase": "ซื้อโพย", "refund": "คืนเครดิต"}


def render_credits(c, me, action, hidden):
    is_admin = me["role"] == "Admin"
    if is_admin:
        c.execute("SELECT 'User', id, username, COALESCE(credit_enabled,FALSE) FROM Users ORDER BY username LIMIT 1000")
        accts = c.fetchall()
        c.execute("SELECT 'Customer', id, name, COALESCE(credit_enabled,FALSE) FROM Customers ORDER BY name LIMIT 2000")
        accts += c.fetchall()
    else:
        subs = get_subtree(c, me["username"])
        low = [n.lower() for n in subs]
        c.execute("SELECT 'User', id, username, COALESCE(credit_enabled,FALSE) FROM Users WHERE LOWER(username) = ANY(%s) AND id<>%s ORDER BY username LIMIT 1000", (low, me["id"]))
        accts = c.fetchall()
        c.execute("SELECT 'Customer', id, name, COALESCE(credit_enabled,FALSE) FROM Customers WHERE LOWER(owner_username) = ANY(%s) ORDER BY name LIMIT 2000", (low,))
        accts += c.fetchall()
    c.execute("SELECT target_type, target_id, COALESCE(SUM(delta),0), COALESCE(SUM(CASE WHEN kind IN ('purchase') THEN -delta END),0) "
              "FROM CreditLedger GROUP BY target_type, target_id")
    bal = {(r[0], r[1]): (float(r[2]), float(r[3])) for r in c.fetchall()}
    rows = [{"kind": k, "id": i, "name": n, "enabled": e, "balance": bal.get((k, i), (0, 0))[0], "used": bal.get((k, i), (0, 0))[1]}
            for k, i, n, e in accts]
    rows.sort(key=lambda r: (not r["enabled"], r["name"].lower()))
    names = {(r["kind"], r["id"]): r["name"] for r in rows}
    my_balance = 0.0
    if not is_admin:
        my_balance = credit_balance(c, "User", me["id"])
        names[("User", me["id"])] = me["username"] + " (คุณ)"
    if is_admin:
        c.execute("SELECT created_at, target_type, target_id, kind, delta, bill_no, note, by_user FROM CreditLedger ORDER BY id DESC LIMIT 60")
    else:
        keys = list(names)
        c.execute("SELECT created_at, target_type, target_id, kind, delta, bill_no, note, by_user FROM CreditLedger ORDER BY id DESC LIMIT 1500")
    ledger = []
    for r in c.fetchall():
        nm = names.get((r[1], r[2]))
        if nm is None and not is_admin:
            continue
        ledger.append((r[0], nm or f"{r[1]}#{r[2]}", _KIND_TH.get(r[3], r[3]), float(r[4]), r[5], r[6], r[7]))
    return _Jinja(_CREDIT_HTML, autoescape=True).render(accts=rows, ledger=ledger[:60], action=action, hidden=hidden, is_admin=is_admin,
                                                    my_balance=my_balance, me_name=me["username"])


# ============================================================ เชื่อมต่อ LINE / Facebook Messenger

CHANNELS = {
    "line": {"title": "LINE Official Account", "fields": [
        ("access_token", "Channel access token (long-lived)", True),
        ("channel_secret", "Channel secret", True)]},
    "messenger": {"title": "Facebook Messenger (Page)", "fields": [
        ("access_token", "Page access token", True),
        ("app_secret", "App secret", True),
        ("verify_token", "Verify token (ตั้งเองอะไรก็ได้ แล้วใช้ค่าเดียวกันในหน้า Webhook ของ Meta)", False)]},
    "telegram": {"title": "Telegram Bot", "fields": [
        ("bot_token", "Bot token (ได้จาก @BotFather เช่น 123456:ABC...)", True)]},
}


def chan_get(c, owner, channel):
    c.execute("SELECT webhook_key, config, COALESCE(enabled, TRUE) FROM ChannelSettings WHERE owner_username=%s AND channel=%s", (owner, channel))
    r = c.fetchone()
    if not r:
        return None
    try:
        cfg = json.loads(r[1] or "{}")
    except ValueError:
        cfg = {}
    return {"key": r[0], "cfg": cfg, "enabled": bool(r[2])}


def chan_by_key(c, channel, key):
    c.execute("SELECT owner_username, config, COALESCE(enabled, TRUE) FROM ChannelSettings WHERE channel=%s AND webhook_key=%s", (channel, key))
    r = c.fetchone()
    if not r or not r[2]:
        return None
    try:
        return {"owner": r[0], "cfg": json.loads(r[1] or "{}")}
    except ValueError:
        return None


def chan_save(c, owner, channel, new_cfg, enabled=True):
    """บันทึกค่า: ช่องที่เว้นว่างจะคงค่าเดิมไว้ (ไม่แสดงรหัสลับกลับมาในหน้าเว็บ)"""
    if channel not in CHANNELS:
        return False
    cur = chan_get(c, owner, channel)
    cfg = dict(cur["cfg"]) if cur else {}
    for k, _label, _secret in CHANNELS[channel]["fields"]:
        v = (new_cfg.get(k) or "").strip()
        if v:
            cfg[k] = v
    now = get_thai_time().strftime("%Y-%m-%d %H:%M:%S")
    if cur:
        c.execute("UPDATE ChannelSettings SET config=%s, enabled=%s, updated_at=%s WHERE owner_username=%s AND channel=%s",
                  (json.dumps(cfg, ensure_ascii=False), enabled, now, owner, channel))
    else:
        c.execute("INSERT INTO ChannelSettings (owner_username, channel, webhook_key, config, enabled, updated_at) VALUES (%s,%s,%s,%s,%s,%s)",
                  (owner, channel, secrets.token_urlsafe(18), json.dumps(cfg, ensure_ascii=False), enabled, now))
    return True


def verify_line_signature(secret, body: bytes, signature: str):
    mac = base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()
    return hmac.compare_digest(mac, signature or "")


def verify_fb_signature(secret, body: bytes, header: str):
    mac = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, header or "")


def _post_json(url, payload, headers):
    req = urllib.request.Request(url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                 headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")[:300]
    except Exception as e:     # เครือข่าย/หมดเวลา
        return 0, str(e)[:200]


def line_send(cfg, to=None, messages=None, reply_token=None):
    tok = cfg.get("access_token")
    if not tok:
        return False, "ยังไม่ได้ตั้งค่า LINE access token"
    hdr = {"Authorization": f"Bearer {tok}"}
    if reply_token:
        st, body = _post_json("https://api.line.me/v2/bot/message/reply", {"replyToken": reply_token, "messages": messages}, hdr)
    else:
        st, body = _post_json("https://api.line.me/v2/bot/message/push", {"to": to, "messages": messages}, hdr)
    return (st == 200), ("" if st == 200 else f"LINE {st}: {body[:120]}")


def messenger_send(cfg, psid, text):
    tok = cfg.get("access_token")
    if not tok:
        return False, "ยังไม่ได้ตั้งค่า Page access token"
    st, body = _post_json("https://graph.facebook.com/v19.0/me/messages?access_token=" + quote(tok),
                          {"recipient": {"id": psid}, "messaging_type": "RESPONSE", "message": {"text": text[:1900]}}, {})
    return (st == 200), ("" if st == 200 else f"Messenger {st}: {body[:120]}")


def _multipart(fields, files):
    """สร้างข้อมูล multipart/form-data (ไม่พึ่งไลบรารีเพิ่ม)  files = {ชื่อฟิลด์: (ชื่อไฟล์, bytes, mime)}"""
    bd = "----lotto" + secrets.token_hex(12)
    out = []
    for k, v in fields.items():
        out.append(f'--{bd}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode("utf-8"))
    for k, (fn, data, mime) in files.items():
        out.append(f'--{bd}\r\nContent-Disposition: form-data; name="{k}"; filename="{fn}"\r\nContent-Type: {mime}\r\n\r\n'.encode("utf-8"))
        out.append(data)
        out.append(b"\r\n")
    out.append(f"--{bd}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={bd}"


def _post_multipart(url, fields, files):
    body, ctype = _multipart(fields, files)
    req = urllib.request.Request(url, data=body, headers={"Content-Type": ctype}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")[:300]
    except Exception as e:
        return 0, str(e)[:200]


def telegram_api(cfg, method, payload=None, files=None, fields=None):
    tok = cfg.get("bot_token")
    if not tok:
        return False, "ยังไม่ได้ตั้งค่า Bot token"
    url = f"https://api.telegram.org/bot{tok}/{method}"
    if files:
        st, body = _post_multipart(url, fields or {}, files)
    else:
        st, body = _post_json(url, payload or {}, {})
    return (st == 200), ("" if st == 200 else f"Telegram {st}: {body[:120]}")


def telegram_send(cfg, chat_id, text):
    return telegram_api(cfg, "sendMessage", {"chat_id": chat_id, "text": text[:4000]})


def telegram_set_webhook(cfg, url, secret):
    return telegram_api(cfg, "setWebhook", {"url": url, "secret_token": secret, "allowed_updates": ["message"]})


def send_text(channel, cfg, ext_id, text, reply_token=None):
    if channel == "line":
        return line_send(cfg, to=ext_id, messages=[{"type": "text", "text": text[:4900]}], reply_token=reply_token)
    if channel == "telegram":
        return telegram_send(cfg, ext_id, text)
    return messenger_send(cfg, ext_id, text)


def messenger_send_image(cfg, psid, png, name="bill.png"):
    tok = cfg.get("access_token")
    if not tok:
        return False, "ยังไม่ได้ตั้งค่า Page access token"
    st, body = _post_multipart("https://graph.facebook.com/v19.0/me/messages?access_token=" + quote(tok),
                               {"recipient": json.dumps({"id": psid}), "messaging_type": "RESPONSE",
                                "message": json.dumps({"attachment": {"type": "image", "payload": {"is_reusable": False}}})},
                               {"filedata": (name, png, "image/png")})
    return (st == 200), ("" if st == 200 else f"Messenger {st}: {body[:120]}")


def telegram_send_image(cfg, chat_id, png, caption="", name="bill.png"):
    return telegram_api(cfg, "sendPhoto", files={"photo": (name, png, "image/png")},
                        fields={"chat_id": str(chat_id), "caption": caption[:1000]})


# ------------------------------------------------------------ บิลเป็นรูปภาพ (PNG)

_FONT_DIRS = [os.environ.get("BILL_FONT_DIR", ""), os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts"),
              "/usr/share/fonts/opentype/tlwg", "/usr/share/fonts/truetype/tlwg"]


def _find_font(bold):
    for d in _FONT_DIRS:
        for nm in (("Loma-Bold.otf", "Garuda-Bold.ttf", "THSarabunNew Bold.ttf") if bold else ("Loma.otf", "Garuda.ttf", "THSarabunNew.ttf")):
            if d and os.path.exists(os.path.join(d, nm)):
                return os.path.join(d, nm)
    return None


def bill_image_png(b, with_disc=False):
    """วาดบิลเป็นไฟล์ PNG (ภาษาไทย)  with_disc=True คือบิลใบที่ 2 (มีส่วนลดและยอดสุทธิ)  ต้องมี Pillow + ฟอนต์ใน ./fonts"""
    from PIL import Image, ImageDraw, ImageFont
    import io
    fr, fb = _find_font(False), _find_font(True)
    if not fr:
        raise RuntimeError("ไม่พบฟอนต์ไทยสำหรับวาดบิล (วางไฟล์ Loma.otf / Loma-Bold.otf ในโฟลเดอร์ fonts)")

    def F(sz, bold=False):
        return ImageFont.truetype((fb if bold and fb else fr), sz)

    W, M = 760, 28
    rows = b["rows"]
    LIM = 150
    shown = rows[:LIM]
    RH, HEAD = 36, 196
    H = HEAD + 44 + RH * len(shown) + (30 if len(rows) > LIM else 0) + (110 if with_disc else 70) + 40
    im = Image.new("RGB", (W, H), "#ffffff")
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, W, 96], fill="#111111")
    d.text((W // 2, 34), str(b["lotto"]), font=F(34, True), fill="#f3e5ab", anchor="mm")
    d.text((W // 2, 72), f"งวดวันที่ {b['draw']}" + ("   (ใบที่ 2 – มีส่วนลด)" if with_disc else ""), font=F(22), fill="#ffffff", anchor="mm")
    y = 112
    d.text((M, y), f"เลขที่บิล {b['bill_no']}", font=F(22, True), fill="#111111")
    d.text((W - M, y), str(b["ts"]), font=F(20), fill="#555555", anchor="ra")
    y += 30
    d.text((M, y), f"ลูกค้า: {b['customer']}", font=F(22), fill="#111111")
    d.text((W - M, y), f"ผู้ขาย: {b['seller']}", font=F(22), fill="#111111", anchor="ra")
    y = HEAD
    if with_disc:
        cols = [("เลข", 0.07, "l"), ("บน/3ตรง", 0.22, "r"), ("ล่าง/โต๊ด", 0.22, "r"), ("รวม", 0.17, "r"), ("ส่วนลด", 0.16, "r"), ("สุทธิ", 0.16, "r")]
    else:
        cols = [("เลข", 0.10, "l"), ("บน/3ตรง", 0.30, "r"), ("ล่าง/โต๊ด", 0.30, "r"), ("รวม", 0.30, "r")]
    inner = W - 2 * M
    xs, x = [], M
    for _n_, wf, al in cols:
        xs.append((x, x + int(inner * wf), al))
        x += int(inner * wf)
    d.rectangle([M, y - 4, W - M, y + 36], fill="#222222")
    for (x0, x1, al), (nm, _w, _a) in zip(xs, cols):
        d.text((x0 + 8 if al == "l" else x1 - 8, y + 16), nm, font=F(20, True), fill="#ffffff", anchor="lm" if al == "l" else "rm")
    y += 40

    def cell(v, rate):
        t = _n(v)
        return t + (f" ({rate:g})" if v and rate else "")
    for i, r in enumerate(shown):
        if i % 2:
            d.rectangle([M, y, W - M, y + RH], fill="#f4f4f4")
        vals = [str(r["num"]), cell(r["top"], r["top_rate"]), cell(r["bot"], r["bot_rate"]), _n(r["total"])]
        if with_disc:
            vals += [_n(r["disc"]), _n(r["net"])]
        for (x0, x1, al), v in zip(xs, vals):
            d.text((x0 + 8 if al == "l" else x1 - 8, y + RH // 2), v, font=F(20, al == "l"), fill="#111111", anchor="lm" if al == "l" else "rm")
        y += RH
    if len(rows) > LIM:
        d.text((M, y + 4), f"... และอีก {len(rows) - LIM} รายการ", font=F(20), fill="#888888")
        y += 30
    d.line([M, y + 6, W - M, y + 6], fill="#111111", width=2)
    y += 20
    d.text((M, y), "ยอดรวม", font=F(26, True), fill="#198754")
    d.text((W - M, y), f"{b['total']:,.2f} บาท", font=F(26, True), fill="#198754", anchor="ra")
    if with_disc:
        y += 38
        d.text((M, y), f"ส่วนลด {b['disc']:,.2f}", font=F(22), fill="#c0392b")
        d.text((W - M, y), f"สุทธิ {b['net']:,.2f} บาท", font=F(26, True), fill="#111111", anchor="ra")
    buf = io.BytesIO()
    im.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def bill_image_token(bill_no, with_disc=False):
    return _sign(f"billimg|{bill_no}|{1 if with_disc else 0}")[:32]


def bill_image_url(base, bill_no, with_disc=False):
    """URL สาธารณะของรูปบิล (เซ็นด้วย SECRET_KEY ใช้ให้ LINE ดึงรูป)"""
    return f"{base.rstrip('/')}/bill-img/{quote(bill_no, safe='')}/{bill_image_token(bill_no, with_disc)}.png" + ("?d=1" if with_disc else "")


def bill_image_response_data(bill_no, token, with_disc):
    """ตรวจโทเค็นแล้วคืน bytes ของ PNG (หรือ None)"""
    if not hmac.compare_digest(token or "", bill_image_token(bill_no, with_disc)):
        return None
    with db() as conn:
        b = bill_dict(conn.cursor(), bill_no)
    return bill_image_png(b, with_disc) if b else None


def _n(v):
    return f"{v:,.2f}".rstrip("0").rstrip(".") if v else "-"


def bill_text(b):
    """ข้อความบิล (ใช้ส่งทาง Messenger / สำรองของ LINE)  b = dict จาก bill_dict"""
    lines = [f"🎟️ {b['lotto']} งวด {b['draw']}", f"เลขที่บิล {b['bill_no']}", f"วันที่ {b['ts']}",
             f"ลูกค้า: {b['customer']}   ผู้ขาย: {b['seller']}", "─" * 18, "เลข | บน/3ตรง | ล่าง/โต๊ด | รวม"]
    for r in b["rows"][:120]:
        lines.append(f"{r['num']} | {_n(r['top'])}{'('+format(r['top_rate'],'g')+')' if r['top_rate'] else ''} | "
                     f"{_n(r['bot'])}{'('+format(r['bot_rate'],'g')+')' if r['bot_rate'] else ''} | {_n(r['total'])}")
    if len(b["rows"]) > 120:
        lines.append(f"... และอีก {len(b['rows']) - 120} รายการ")
    lines += ["─" * 18, f"ยอดรวม {b['total']:,.2f} บาท"]
    return "\n".join(lines)


def bill_flex(b):
    """LINE Flex Message หน้าตาเป็นบิล (ไม่ต้องใช้ไฟล์รูป/ฟอนต์บนเซิร์ฟเวอร์)"""
    def t(text, **kw):
        return {"type": "text", "text": str(text), "size": kw.pop("size", "sm"), **kw}

    def row(cells, bold=False, color=None):
        out = []
        for i, (txt, flex, align) in enumerate(cells):
            kw = {"flex": flex, "align": align, "wrap": True}
            if bold:
                kw["weight"] = "bold"
            if color:
                kw["color"] = color
            out.append(t(txt, **kw))
        return {"type": "box", "layout": "horizontal", "contents": out, "margin": "xs"}

    body = [
        row([(b["ts"], 1, "start"), (b["bill_no"], 1, "end")]),
        row([("ลูกค้า: " + b["customer"], 1, "start"), ("ผู้ขาย: " + b["seller"], 1, "end")]),
        {"type": "separator", "margin": "md"},
        row([("เลข", 2, "start"), ("บน/3ตรง", 3, "end"), ("ล่าง/โต๊ด", 3, "end"), ("รวม", 2, "end")], bold=True),
    ]
    for r in b["rows"][:60]:
        body.append(row([(r["num"], 2, "start"),
                         (_n(r["top"]) + (f" ({r['top_rate']:g})" if r["top_rate"] and r["top"] else ""), 3, "end"),
                         (_n(r["bot"]) + (f" ({r['bot_rate']:g})" if r["bot_rate"] and r["bot"] else ""), 3, "end"),
                         (_n(r["total"]), 2, "end")]))
    if len(b["rows"]) > 60:
        body.append(t(f"... และอีก {len(b['rows']) - 60} รายการ", color="#888888"))
    body += [{"type": "separator", "margin": "md"},
             row([("ยอดรวม", 1, "start"), (f"{b['total']:,.2f} บาท", 1, "end")], bold=True, color="#198754")]
    return {"type": "flex", "altText": f"บิล {b['bill_no']} ยอด {b['total']:,.2f}",
            "contents": {"type": "bubble", "size": "mega",
                         "header": {"type": "box", "layout": "vertical", "backgroundColor": "#111111", "contents": [
                             t(b["lotto"], color="#f3e5ab", weight="bold", size="lg", align="center"),
                             t("งวด " + str(b["draw"]), color="#ffffff", align="center")]},
                         "body": {"type": "box", "layout": "vertical", "contents": body}}}


def bill_dict(c, bill_no):
    """โหลดบิลที่บันทึกแล้วจาก Transactions เป็น dict (สำหรับส่งให้ลูกค้า)"""
    c.execute("SELECT id, num, type, amount, status, payout_rate, username, timestamp, customer_name, lotto_name, draw_date, "
              "discount, net, customer_id, customer_type FROM Transactions WHERE bill_no=%s ORDER BY id", (bill_no,))
    rs = c.fetchall()
    if not rs:
        return None
    drafts = [(r[0], r[1], r[3], r[4], r[2], r[5], r[11], r[12]) for r in rs]
    rows, tot = group_draft(drafts)
    return {"bill_no": bill_no, "lotto": rs[0][9], "draw": rs[0][10], "ts": rs[0][7], "customer": rs[0][8], "seller": rs[0][6],
            "rows": rows, "total": tot["amt"], "disc": tot["disc"], "net": tot["net"],
            "customer_id": rs[0][13], "customer_type": rs[0][14]}


def send_bill_to_customer(c, owner, bill, base_url=""):
    """ส่งบิลใบแรก (ไม่มีส่วนลด) เป็น "รูปภาพ" ให้ลูกค้าทุกช่องทางที่ผูกไว้ ถ้าวาดรูป/ส่งรูปไม่ได้จะสำรองเป็นข้อความ
    คืน (จำนวนที่ส่งสำเร็จ, [ข้อผิดพลาด])"""
    if not bill or bill.get("customer_type") != "Customer":
        return 0, []
    c.execute("SELECT channel, external_id FROM ChannelLinks WHERE owner_username=%s AND customer_id=%s", (owner, bill["customer_id"]))
    links = c.fetchall()
    sent, errs = 0, []
    png = None
    if links:
        try:
            png = bill_image_png(bill)
        except Exception as e:
            errs.append("วาดรูปบิลไม่สำเร็จ ส่งเป็นข้อความแทน: " + str(e)[:80])
    cap = f"บิล {bill['bill_no']} ยอด {bill['total']:,.2f} บาท"
    for channel, ext in links:
        ch = chan_get(c, owner, channel)
        if not ch or not ch["enabled"]:
            continue
        ok, err = False, ""
        if channel == "line":
            if png and base_url.startswith("https://"):
                u = bill_image_url(base_url, bill["bill_no"])
                ok, err = line_send(ch["cfg"], to=ext, messages=[{"type": "image", "originalContentUrl": u, "previewImageUrl": u}])
            if not ok:
                ok, err = line_send(ch["cfg"], to=ext, messages=[bill_flex(bill)])
        elif channel == "telegram":
            if png:
                ok, err = telegram_send_image(ch["cfg"], ext, png, cap)
            if not ok:
                ok, err = telegram_send(ch["cfg"], ext, bill_text(bill))
        else:
            if png:
                ok, err = messenger_send_image(ch["cfg"], ext, png)
            if not ok:
                ok, err = messenger_send(ch["cfg"], ext, bill_text(bill))
        sent += 1 if ok else 0
        if not ok:
            errs.append(err)
    return sent, errs


HELP_TEXT = ("วิธีส่งโพย:\n14=10*10,41=10*10\n123=100*50\n(เลข=ยอดบน*ยอดล่าง คั่นด้วยคอมมาหรือขึ้นบรรทัดใหม่)\n"
             "เลขยอดเท่ากัน: 14,41=10*10  ไม่ซื้อฝั่งใดใส่ 0 เช่น 456=0*50\n"
             "เลือกหวย: พิมพ์ \"หวย ชื่อหวย\"   ดูเครดิต: พิมพ์ \"เครดิต\"")


def handle_chat_message(c, owner, channel, ext_id, text):
    """ประมวลผลข้อความจากลูกค้าในแชท  คืนข้อความตอบกลับ"""
    text = (text or "").strip()
    if not text:
        return None
    c.execute("SELECT id, customer_id, campaign_id FROM ChannelLinks WHERE channel=%s AND external_id=%s AND owner_username=%s",
              (channel, ext_id, owner))
    link = c.fetchone()
    m = re.fullmatch(r"(?:ผูก|link|bind)\s+([A-Za-z0-9]{4,10})", text, re.I)
    if m:
        c.execute("SELECT id, name FROM Customers WHERE LOWER(owner_username)=LOWER(%s) AND UPPER(link_code)=UPPER(%s)", (owner, m.group(1)))
        cu = c.fetchone()
        if not cu:
            return "ไม่พบรหัสนี้ กรุณาตรวจสอบรหัสผูกบัญชีกับผู้ขายอีกครั้ง"
        now = get_thai_time().strftime("%Y-%m-%d %H:%M:%S")
        if link:
            c.execute("UPDATE ChannelLinks SET customer_id=%s, campaign_id=NULL WHERE id=%s", (cu[0], link[0]))
        else:
            c.execute("INSERT INTO ChannelLinks (channel, external_id, owner_username, customer_id, created_at) VALUES (%s,%s,%s,%s,%s)",
                      (channel, ext_id, owner, cu[0], now))
        return f"ผูกบัญชีกับ \"{cu[1]}\" สำเร็จ ✅\n\n" + HELP_TEXT
    if not link:
        return "ยังไม่ได้ผูกบัญชี กรุณาพิมพ์: ผูก <รหัสลูกค้า> (ขอรหัสจากผู้ขาย)"
    link_id, cust_id, camp_id = link
    if re.fullmatch(r"(เครดิต|credit)", text, re.I):
        if not credit_enabled(c, "Customer", cust_id):
            return "บัญชีของคุณไม่ได้ใช้ระบบเครดิต"
        return f"เครดิตคงเหลือ {credit_balance(c, 'Customer', cust_id):,.2f} บาท"

    c.execute("SELECT id FROM LotteryCampaigns WHERE status='Active' ORDER BY id DESC")
    open_camps = []
    for (cid,) in c.fetchall():
        camp = get_campaign(c, cid)
        if camp and campaign_open(camp)[0]:
            open_camps.append(camp)
    m = re.match(r"(?:หวย|lotto)\s+(.+)", text, re.I)
    if m:
        kw = m.group(1).strip().lower()
        hit = [k for k in open_camps if kw in (k["lotto_name"] or "").lower()]
        if len(hit) == 1:
            c.execute("UPDATE ChannelLinks SET campaign_id=%s WHERE id=%s", (hit[0]["id"], link_id))
            return f"เลือกหวย: {hit[0]['lotto_name']} งวด {hit[0]['draw_date']} ✅ ส่งโพยได้เลย"
        if not hit:
            return "ไม่พบหวยที่เปิดรับตามชื่อนี้\nหวยที่เปิดรับ:\n" + "\n".join("• " + k["lotto_name"] for k in open_camps[:15])
        return "พบหลายหวย กรุณาระบุให้ชัดขึ้น:\n" + "\n".join("• " + k["lotto_name"] for k in hit[:15])

    entries, errors = parse_quick(text)
    if not entries:
        return ("อ่านโพยไม่ได้\n" + "\n".join(errors[:5]) + "\n\n" if errors else "") + HELP_TEXT
    camp = next((k for k in open_camps if k["id"] == camp_id), None)
    if not camp:
        if len(open_camps) == 1:
            camp = open_camps[0]
        elif not open_camps:
            return "ขณะนี้ไม่มีหวยที่เปิดรับ"
        else:
            return "มีหวยเปิดรับหลายรายการ กรุณาเลือกก่อน พิมพ์: หวย <ชื่อหวย>\n" + "\n".join("• " + k["lotto_name"] for k in open_camps[:15])
    rates, _ = get_rates(c, str(cust_id), camp["lotto_name"])
    if not rates:
        return "ยังไม่ได้ตั้งเรตของคุณสำหรับหวยนี้ กรุณาติดต่อผู้ขาย"
    blocked = get_blocked_map(c, camp["lotto_name"], camp["draw_date"])
    rows, rejected, invalid = make_draft_rows(rates, blocked, entries, owner, "Customer", cust_id, camp)
    if rows:
        c.executemany("INSERT INTO TempDraft (username, customer_id, customer_type, num, amt_teng, type, payout_rate, discount, net, "
                      "status, lotto_name, draw_date) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", rows)
    total = sum(r[4] for r in rows)
    msg = [f"รับโพยแล้ว {len(rows)} รายการ ยอด {total:,.2f} บาท\n{camp['lotto_name']} งวด {camp['draw_date']}\nรอผู้ขายตรวจและออกบิลให้ค่ะ"] if rows else ["ไม่มีรายการที่บันทึกได้"]
    if rejected:
        msg.append("เลขปิดรับ: " + ", ".join(rejected[:30]))
    if errors:
        msg.append("อ่านไม่ได้: " + "; ".join(errors[:3]))
    return "\n".join(msg)


# ------------------------------------------------------------ ประมวลผล webhook (ใช้ร่วมกันทั้งสองระบบ)

def process_webhook(channel, key, body: bytes, headers):
    """คืนรหัสสถานะ HTTP  headers = dict ที่คีย์เป็นตัวพิมพ์เล็ก"""
    replies, cfg = [], None
    try:
        data = json.loads(body.decode("utf-8") or "{}")
    except ValueError:
        return 400
    with db() as conn:
        c = conn.cursor()
        ch = chan_by_key(c, channel, key)
        if not ch:
            return 404
        owner, cfg = ch["owner"], ch["cfg"]
        if channel == "line":
            if not cfg.get("channel_secret") or not verify_line_signature(cfg["channel_secret"], body, headers.get("x-line-signature", "")):
                return 403
            for ev in data.get("events") or []:
                msg = ev.get("message") or {}
                uid = (ev.get("source") or {}).get("userId")
                if ev.get("type") == "message" and msg.get("type") == "text" and uid:
                    t = handle_chat_message(c, owner, "line", uid, msg.get("text", ""))
                    if t:
                        replies.append((uid, t, ev.get("replyToken")))
        elif channel == "messenger":
            if not cfg.get("app_secret") or not verify_fb_signature(cfg["app_secret"], body, headers.get("x-hub-signature-256", "")):
                return 403
            for entry in data.get("entry") or []:
                for m in entry.get("messaging") or []:
                    psid, text = (m.get("sender") or {}).get("id"), (m.get("message") or {}).get("text")
                    if psid and text and not (m.get("message") or {}).get("is_echo"):
                        t = handle_chat_message(c, owner, "messenger", psid, text)
                        if t:
                            replies.append((psid, t, None))
        elif channel == "telegram":
            # Telegram ส่งรหัสลับที่เราตั้งตอน setWebhook มาใน header (ใช้ webhook_key เป็นรหัส)
            if not hmac.compare_digest(headers.get("x-telegram-bot-api-secret-token", ""), key):
                return 403
            msg = data.get("message") or {}
            chat_id = (msg.get("chat") or {}).get("id")
            text = msg.get("text")
            if chat_id and text and not (msg.get("from") or {}).get("is_bot"):
                text = re.sub(r"^/(start|help)(@\w+)?\s*", "", text).strip() or "help"
                if text.lower() == "help":
                    replies.append((str(chat_id), "ยินดีต้อนรับ \U0001F44B ผูกบัญชีก่อนโดยพิมพ์: ผูก <รหัสลูกค้า>\n\n" + HELP_TEXT, None))
                else:
                    t = handle_chat_message(c, owner, "telegram", str(chat_id), text)
                    if t:
                        replies.append((str(chat_id), t, None))
        else:
            return 404
    for ext, text, token in replies:
        ok, err = send_text(channel, cfg, ext, text, reply_token=token)
        if not ok:
            print(channel, "reply failed:", err)
    return 200


# ------------------------------------------------------------ หน้าตั้งค่าเชื่อมต่อแชท (ใช้ร่วมกันทั้งสองระบบ)

_INTEG_HTML = """
<div class="container my-3" style="max-width:900px">
  <h3 class="fw-bold text-primary mb-1">🔗 เชื่อมต่อแชท (LINE / Messenger / Telegram)</h3>
  <p class="text-muted small">ตั้งค่าบัญชีของคุณเองเพื่อ ① รับโพยจากลูกค้าทางแชทเข้าโพยร่าง ② ส่งบิลเป็นรูปภาพให้ลูกค้าเมื่อกด "บันทึกบิล/ส่งบิล" ลูกค้าผูกบัญชีโดยพิมพ์ <code>ผูก รหัส</code> ในแชท (รหัสดูได้ที่หน้า "จัดการลูกค้า")</p>
  {% for ch in channels %}
  <div class="card shadow-sm p-3 mb-3">
    <h5 class="fw-bold">{{ ch.title }} {% if ch.saved %}<span class="badge {{ 'bg-success' if ch.enabled else 'bg-secondary' }}">{{ 'เปิดใช้งาน' if ch.enabled else 'ปิดอยู่' }}</span>{% else %}<span class="badge bg-light text-dark border">ยังไม่ตั้งค่า</span>{% endif %}</h5>
    {% if ch.key %}
    <div class="mb-2"><label class="form-label small fw-bold mb-0">Webhook URL (นำไปวางในหน้าตั้งค่าของ {{ {'line':'LINE Developers','messenger':'Meta for Developers','telegram':'Telegram (ระบบตั้งให้อัตโนมัติเมื่อกดบันทึก)'}[ch.id] }})</label>
      <input class="form-control form-control-sm" readonly value="{{ ch.url }}" onclick="this.select()"></div>
    {% else %}<div class="alert alert-light border py-1 small">บันทึกค่าด้านล่างก่อน ระบบจะสร้าง Webhook URL ให้</div>{% endif %}
    <form method="POST" action="{{ action }}">
      {% for k, v in hidden.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
      <input type="hidden" name="channel" value="{{ ch.id }}">
      {% for f in ch.fields %}
      <div class="mb-2"><label class="form-label small fw-bold mb-0">{{ f.label }}</label>
        <input type="{{ 'password' if f.secret else 'text' }}" name="{{ f.key }}" class="form-control form-control-sm" autocomplete="off"
          placeholder="{{ 'ตั้งค่าแล้ว — เว้นว่างเพื่อคงค่าเดิม' if f.has else '' }}" value="{{ '' if f.secret else f.value }}"></div>
      {% endfor %}
      <div class="form-check mb-2"><input class="form-check-input" type="checkbox" name="enabled" value="1" id="en_{{ ch.id }}" {{ 'checked' if ch.enabled or not ch.saved }}><label class="form-check-label small" for="en_{{ ch.id }}">เปิดใช้งาน</label></div>
      <button class="btn btn-primary btn-sm fw-bold px-4">💾 บันทึก</button>
    </form>
    <details class="mt-2 small"><summary class="fw-bold">วิธีตั้งค่า</summary>
      {% if ch.id == 'line' %}
      <ol class="mb-0"><li>สร้าง Messaging API channel ที่ LINE Developers Console</li><li>คัดลอก Channel secret และออก Channel access token (long-lived) มาใส่ด้านบน</li><li>วาง Webhook URL ในแท็บ Messaging API → เปิด "Use webhook"</li><li>ลูกค้าเพิ่มเพื่อน OA แล้วพิมพ์ <code>ผูก รหัสลูกค้า</code></li></ol>
      {% elif ch.id == 'telegram' %}
      <ol class="mb-0"><li>เปิดแชท @BotFather ใน Telegram พิมพ์ <code>/newbot</code> ตั้งชื่อบอท แล้วคัดลอก Bot token มาใส่ด้านบน</li><li>กด "บันทึก" — ระบบจะตั้ง Webhook ให้อัตโนมัติ</li><li>ลูกค้าเปิดบอทของคุณ กด Start แล้วพิมพ์ <code>ผูก รหัสลูกค้า</code></li></ol>
      {% else %}
      <ol class="mb-0"><li>สร้างแอปที่ Meta for Developers เพิ่มผลิตภัณฑ์ Messenger และเชื่อมกับ Facebook Page</li><li>คัดลอก Page access token และ App secret มาใส่ด้านบน ตั้ง Verify token เอง</li><li>ที่หน้า Webhooks ใส่ Callback URL (ด้านบน) และ Verify token เดียวกัน แล้ว subscribe เหตุการณ์ <code>messages</code></li><li>ลูกค้าส่งข้อความหาเพจแล้วพิมพ์ <code>ผูก รหัสลูกค้า</code></li></ol>
      {% endif %}
    </details>
  </div>
  {% endfor %}
</div>
"""


def render_integrations(c, me, base, action, hidden):
    channels = []
    for cid, meta in CHANNELS.items():
        cur = chan_get(c, me["username"], cid)
        cfg = cur["cfg"] if cur else {}
        channels.append({"id": cid, "title": meta["title"], "saved": bool(cur), "enabled": bool(cur and cur["enabled"]),
                         "key": cur["key"] if cur else "", "url": f"{base}/webhook/{cid}/{cur['key']}" if cur else "",
                         "fields": [{"key": k, "label": lb, "secret": sec, "has": bool(cfg.get(k)), "value": cfg.get(k, "") if not sec else ""}
                                    for k, lb, sec in meta["fields"]]})
    return _Jinja(_INTEG_HTML, autoescape=True).render(channels=channels, action=action, hidden=hidden)


def integrations_save(c, me, base, channel, form):
    """บันทึกการเชื่อมต่อ (ใช้ร่วมกัน)  คืน (ok, ข้อความ)"""
    if not chan_save(c, me["username"], channel, {k: str(v) for k, v in form.items()}, enabled=bool(form.get("enabled"))):
        return False, "ช่องทางไม่ถูกต้อง"
    note = "บันทึกการเชื่อมต่อแล้ว"
    if channel == "telegram":
        cur = chan_get(c, me["username"], "telegram")
        if cur and cur["enabled"]:
            ok, err = telegram_set_webhook(cur["cfg"], f"{base}/webhook/telegram/{cur['key']}", cur["key"])
            note += " · ตั้ง Webhook ของ Telegram อัตโนมัติแล้ว ✅" if ok else f" · ตั้ง Webhook อัตโนมัติไม่สำเร็จ: {err}"
    return True, note


def public_base(base):
    """Render อยู่หลัง proxy จึงบังคับ https ถ้าไม่ใช่ localhost"""
    base = str(base).rstrip("/")
    if base.startswith("http://") and "localhost" not in base and "127.0.0.1" not in base:
        base = "https://" + base[len("http://"):]
    return base
