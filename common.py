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
import math
import os
import re
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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
    บัญชีเก่าที่ไม่มี upline (parent_user ว่าง และไม่ใช่แอดมิน) ถือเป็นสายตรงของแอดมินคนแรก"""
    c.execute("SELECT id, username, role FROM Users WHERE id<>%s AND (LOWER(parent_user)=LOWER(%s) OR "
              "(%s AND (parent_user IS NULL OR BTRIM(parent_user)='') AND LOWER(role)<>'admin')) ORDER BY id DESC",
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
                       AND (u.parent_user IS NULL OR BTRIM(u.parent_user) = '') AND LOWER(u.role) <> 'admin'))
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
    return {"node": node, "path": path, "rows": rows, "total": total,
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
 document.getElementById('ls-upd').textContent='อัปเดตล่าสุด '+d.updated;}
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
    # บัญชีเก่าที่ไม่มี upline (parent_user ว่าง) -> ให้เป็นสายตรงของแอดมินคนแรก เพื่อให้โผล่ในรายชื่อและสิทธิ์ทำงานได้
    "UPDATE Users SET parent_user = (SELECT username FROM Users WHERE role = 'Admin' ORDER BY id LIMIT 1) "
    "WHERE (parent_user IS NULL OR BTRIM(parent_user) = '') AND role <> 'Admin' "
    "AND EXISTS (SELECT 1 FROM Users WHERE role = 'Admin')",
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
