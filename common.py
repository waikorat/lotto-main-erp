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


def get_subtree(c, username):
    """username ของตัวเอง + ลูกข่ายทุกชั้น (กัน loop ด้วย UNION)"""
    c.execute(
        """WITH RECURSIVE t AS (
               SELECT username FROM Users WHERE username=%s
               UNION
               SELECT u.username FROM Users u JOIN t ON u.parent_user = t.username
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
    if me["role"] == "Admin":
        c.execute("SELECT id, name, owner_username FROM Customers ORDER BY id DESC")
        custs = c.fetchall()
        c.execute("SELECT id, username FROM Users WHERE id<>%s ORDER BY id DESC", (me["id"],))
        users = c.fetchall()
    else:
        c.execute("SELECT id, name, owner_username FROM Customers WHERE LOWER(owner_username)=LOWER(%s) ORDER BY id DESC",
                  (me["username"],))
        custs = c.fetchall()
        c.execute("SELECT id, username FROM Users WHERE LOWER(parent_user)=LOWER(%s) AND id<>%s ORDER BY id DESC",
                  (me["username"], me["id"]))
        users = c.fetchall()
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
    c.execute("SELECT id, lotto_name, draw_date, status, close_time FROM LotteryCampaigns WHERE id=%s", (campaign_id,))
    r = c.fetchone()
    if not r:
        return None
    return {"id": r[0], "lotto_name": clean_name(r[1]), "draw_date": clean_name(r[2]), "status": r[3], "close_time": r[4]}


def campaign_open(camp):
    """คืน (เปิดรับไหม, เหตุผลถ้าปิด) — เช็คฝั่งเซิร์ฟเวอร์เสมอ ไม่พึ่ง JavaScript"""
    if camp["status"] != "Active":
        return False, "งวดนี้ถูกปิดโดยผู้ดูแลระบบ"
    s = seconds_until(camp["close_time"])
    if s is not None and s <= 0:
        return False, "หวยนี้ปิดรับแทงแล้ว"
    return True, ""


CATEGORY_ORDER = ["รัฐบาลไทย", "ฮานอย", "ลาว", "หุ้นต่างประเทศ", "อื่นๆ"]
_STOCK_KEYS = ["หุ้น", "nasdaq", "dow", "ดาวโจนส์", "s&p", "nikkei", "นิเคอิ", "dax",
               "เยอรมัน", "nifty", "อินเดีย", "kse", "ปากีสถาน"]


def categorize(name):
    n = (name or "").lower()
    if "รัฐบาล" in n:
        return "รัฐบาลไทย"
    if "ฮานอย" in n:
        return "ฮานอย"
    if "ลาว" in n:
        return "ลาว"
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
