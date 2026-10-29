from fastapi import FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Template
import psycopg2
from datetime import datetime, timedelta
import itertools
import re

app = FastAPI(title="Lotto ERP Full Enterprise Cloud", debug=True)

# ===== ตั้งค่าฐานข้อมูล =====
DB_URI = "postgresql://postgres.mpyswshlrxwpirzdexrn:Clublifekorat3888@aws-0-ap-northeast-1.pooler.supabase.com:6543/postgres"

def connect_db():
    return psycopg2.connect(DB_URI)

# ฟังก์ชันดึงเวลาไทย (UTC+7)
def get_thai_time():
    return datetime.utcnow() + timedelta(hours=7)

@app.on_event("startup")
def startup_db():
    try:
        conn = connect_db()
        c = conn.cursor()
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS Customers (
                id SERIAL PRIMARY KEY,
                name TEXT,
                owner_username TEXT,
                discount_type INTEGER DEFAULT 1,
                disc_total NUMERIC DEFAULT 0,
                disc_3d NUMERIC DEFAULT 0,
                disc_2d NUMERIC DEFAULT 0,
                pay_3d NUMERIC DEFAULT 500,
                pay_3tod NUMERIC DEFAULT 100,
                pay_2d NUMERIC DEFAULT 70
            );
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS LotteryCampaigns (
                id SERIAL PRIMARY KEY,
                lotto_name TEXT,
                draw_date TEXT,
                status TEXT DEFAULT 'Active',
                close_time TEXT
            );
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS BlockedNumbers (
                id SERIAL PRIMARY KEY,
                draw_date TEXT,
                raw_num TEXT,
                status TEXT,
                type TEXT
            );
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS TempDraft (
                id SERIAL PRIMARY KEY,
                username TEXT,
                customer_id TEXT,
                customer_type TEXT,
                num TEXT,
                amt_teng NUMERIC DEFAULT 0,
                amt_tod NUMERIC DEFAULT 0,
                type TEXT,
                payout_rate NUMERIC DEFAULT 0,
                discount NUMERIC DEFAULT 0,
                net NUMERIC DEFAULT 0,
                status TEXT DEFAULT 'ปกติ'
            );
        """)
        conn.commit()

        migrations = [
            "ALTER TABLE BlockedNumbers ADD COLUMN IF NOT EXISTS is_raw BOOLEAN DEFAULT FALSE;",
            "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'ปกติ';",
            "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS amt_teng NUMERIC DEFAULT 0;",
            "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS amt_tod NUMERIC DEFAULT 0;",
            "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS payout_rate NUMERIC DEFAULT 0;",
            "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS discount NUMERIC DEFAULT 0;",
            "ALTER TABLE TempDraft ADD COLUMN IF NOT EXISTS net NUMERIC DEFAULT 0;",
            "ALTER TABLE Customers ADD COLUMN IF NOT EXISTS disc_3d NUMERIC DEFAULT 0;",
            "ALTER TABLE Customers ADD COLUMN IF NOT EXISTS disc_2d NUMERIC DEFAULT 0;",
            "ALTER TABLE Customers ADD COLUMN IF NOT EXISTS disc_total NUMERIC DEFAULT 0;",
            "ALTER TABLE Customers ADD COLUMN IF NOT EXISTS disc_run NUMERIC DEFAULT 0;",
            "ALTER TABLE Customers ADD COLUMN IF NOT EXISTS pay_run_top NUMERIC DEFAULT 3;",
            "ALTER TABLE Customers ADD COLUMN IF NOT EXISTS pay_run_bot NUMERIC DEFAULT 4;",
            "ALTER TABLE Users ADD COLUMN IF NOT EXISTS disc_total NUMERIC DEFAULT 0;",
            "ALTER TABLE Users ADD COLUMN IF NOT EXISTS disc_3d NUMERIC DEFAULT 0;",
            "ALTER TABLE Users ADD COLUMN IF NOT EXISTS disc_2d NUMERIC DEFAULT 0;",
            "ALTER TABLE Users ADD COLUMN IF NOT EXISTS disc_run NUMERIC DEFAULT 0;",
            "ALTER TABLE Users ADD COLUMN IF NOT EXISTS pay_3d NUMERIC DEFAULT 500;",
            "ALTER TABLE Users ADD COLUMN IF NOT EXISTS pay_3tod NUMERIC DEFAULT 100;",
            "ALTER TABLE Users ADD COLUMN IF NOT EXISTS pay_2d NUMERIC DEFAULT 70;",
            "ALTER TABLE Users ADD COLUMN IF NOT EXISTS pay_run_top NUMERIC DEFAULT 3;",
            "ALTER TABLE Users ADD COLUMN IF NOT EXISTS pay_run_bot NUMERIC DEFAULT 4;",
            "ALTER TABLE LotteryCampaigns ADD COLUMN IF NOT EXISTS close_time TEXT;",
            "ALTER TABLE LotteryCampaigns ALTER COLUMN close_time TYPE TEXT USING close_time::text;",
            "ALTER TABLE LotteryCampaigns ADD COLUMN IF NOT EXISTS result_timestamp TEXT;"
        ]
        for mig in migrations:
            try:
                c.execute(mig)
                conn.commit()
            except:
                conn.rollback()

        c.execute("""
            CREATE TABLE IF NOT EXISTS Transactions (
                id SERIAL PRIMARY KEY,
                draw_date TEXT,
                timestamp TEXT,
                username TEXT,
                customer_id INTEGER,
                customer_name TEXT,
                customer_type TEXT,
                bill_no TEXT,
                num TEXT,
                type TEXT,
                amount NUMERIC DEFAULT 0,
                status TEXT,
                discount NUMERIC DEFAULT 0,
                net NUMERIC DEFAULT 0,
                payout_rate NUMERIC DEFAULT 0,
                lotto_name TEXT
            );
        """)
        try:
            c.execute("ALTER TABLE Transactions ADD COLUMN IF NOT EXISTS lotto_name TEXT;")
            conn.commit()
        except:
            conn.rollback()
            
        c.execute("""
            CREATE TABLE IF NOT EXISTS DrawResults (
                id SERIAL PRIMARY KEY,
                draw_date TEXT UNIQUE,
                prize_1 TEXT,
                bottom_2 TEXT
            );
        """)
        conn.commit()

        c.execute("""
            CREATE TABLE IF NOT EXISTS CustomerLottoRates (
                id SERIAL PRIMARY KEY,
                customer_id INT REFERENCES Customers(id) ON DELETE CASCADE,
                lotto_name VARCHAR(100) NOT NULL,
                pay_3d NUMERIC(10,2) DEFAULT 500,
                pay_3tod NUMERIC(10,2) DEFAULT 100,
                pay_2d NUMERIC(10,2) DEFAULT 70,
                pay_run_top NUMERIC(10,2) DEFAULT 3.2,
                pay_run_bot NUMERIC(10,2) DEFAULT 4.2,
                disc_3d NUMERIC(5,2) DEFAULT 0,
                disc_2d NUMERIC(5,2) DEFAULT 0,
                disc_run NUMERIC(5,2) DEFAULT 0,
                disc_total NUMERIC(5,2) DEFAULT 0,
                UNIQUE(customer_id, lotto_name)
            );
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print("Startup DB Init Warning:", e)

# ================= Helper Functions =================

def extract_date_to_string(draw_date):
    nums = re.findall(r'\d+', draw_date)
    if len(nums) >= 3:
        d = str(nums[0]).zfill(2)
        m = str(nums[1]).zfill(2)
        y = str(nums[2])[-2:]
        return f"{d}{m}{y}"
    elif len(nums) >= 2:
        return f"{nums[0].zfill(2)}{nums[1].zfill(2)}XX"
    return get_thai_time().strftime("%d%m%y")

def generate_bill_no(lotto_name, draw_date, c_id):
    l_name = str(lotto_name).lower() if lotto_name else ""
    if 'รัฐบาล' in l_name or 'ไทย' in l_name: prefix = 'TH'
    elif 'ลาว' in l_name: prefix = 'LO'
    elif 'ฮานอย' in l_name or 'เวียดนาม' in l_name: prefix = 'HN'
    elif 'มาเลย์' in l_name: prefix = 'MY'
    elif 'หุ้น' in l_name: prefix = 'ST'
    elif 'ยี่กี' in l_name or 'ปิงปอง' in l_name: prefix = 'YG'
    else: prefix = 'OT'
    
    date_part = extract_date_to_string(draw_date)
    
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT COUNT(DISTINCT bill_no) FROM Transactions WHERE customer_id=%s AND (draw_date=%s OR draw_date ILIKE %s)", (c_id, draw_date, f"%{draw_date}%"))
        count = c.fetchone()[0]
        conn.close()
    except:
        count = 0
        
    seq = f"{count + 1:02d}"
    return f"{prefix}{date_part}-{c_id}-B{seq}"

def get_all_blocked_for_draw(draw_date):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT raw_num, status FROM BlockedNumbers WHERE (draw_date = %s OR draw_date ILIKE %s)", (draw_date, f"%{draw_date}%"))
        rows = c.fetchall()
        conn.close()
        return {str(r[0]).strip(): str(r[1]) for r in rows if r[0]}
    except:
        return {}

def get_blocked_display_data(draw_date):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT raw_num, status, type FROM BlockedNumbers WHERE (draw_date = %s OR draw_date ILIKE %s) AND is_raw = TRUE", (draw_date, f"%{draw_date}%"))
        rows = c.fetchall()
        if not rows:
            c.execute("SELECT raw_num, status, type FROM BlockedNumbers WHERE (draw_date = %s OR draw_date ILIKE %s)", (draw_date, f"%{draw_date}%"))
            rows = c.fetchall()
        conn.close()
        l_c, l_3, l_2 = [], [], []
        seen_c, seen_3, seen_2 = set(), set(), set()
        for r_num, status_val, type_val in rows:
            if not r_num: continue
            num_str = str(r_num).strip()
            if status_val == "ปิดรับ":
                if num_str not in seen_c:
                    seen_c.add(num_str)
                    l_c.append(num_str)
            else:
                if len(num_str) == 3 or type_val == "3ตัว":
                    if num_str not in seen_3:
                        seen_3.add(num_str)
                        l_3.append(num_str)
                elif len(num_str) == 2 or type_val == "2ตัว":
                    if num_str not in seen_2:
                        seen_2.add(num_str)
                        l_2.append(num_str)
        return ", ".join(l_c), ", ".join(l_3), ", ".join(l_2)
    except:
        return "", "", ""

def check_number_blocked_status(draw_date, num_str):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT status FROM BlockedNumbers WHERE (draw_date = %s OR draw_date ILIKE %s) AND raw_num = %s", (draw_date, f"%{draw_date}%", num_str))
        res = c.fetchone()
        conn.close()
        if res: return res[0]
        return "ปกติ"
    except:
        return "ปกติ"

def get_current_campaign_close_time(draw_date):
    if not draw_date or draw_date == "เลือกงวด": return None
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT close_time FROM LotteryCampaigns WHERE draw_date = %s OR draw_date ILIKE %s", (draw_date, f"%{draw_date}%"))
        res = c.fetchone()
        conn.close()
        return res[0] if res and res[0] else None
    except:
        return None

# ================= HTML Templates =================

LAYOUT = """
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lotto ERP - ระบบบริหารจัดการหวย</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background-color: #f0f2f5; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; overflow-x: hidden; }
        .top-navbar { background-color: #1a1a1a; color: white; padding: 8px 15px; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #ffc107; }
        .top-nav-links { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .top-nav-links a { background-color: #ffc107; color: #000; font-weight: bold; padding: 5px 12px; border-radius: 4px; text-decoration: none; font-size: 0.9rem; transition: 0.2s; }
        .top-nav-links a:hover { background-color: #e0a800; }
        .ticker-banner { background-color: #dc3545; color: white; text-align: center; padding: 6px; font-weight: bold; font-size: 0.95rem; display: flex; justify-content: center; gap: 20px; align-items: center; }
        .main-wrapper { display: flex; min-height: calc(100vh - 100px); }
        .sidebar { width: 260px; background-color: #1a1a1a; color: white; border-right: 2px solid #ffc107; padding: 15px 10px; flex-shrink: 0; }
        .user-profile-box { background-color: #2b2b2b; border: 1px solid #ffc107; border-radius: 6px; text-align: center; padding: 12px; margin-bottom: 20px; }
        .sidebar-section-title { color: #ffc107; font-weight: bold; font-size: 0.95rem; margin-top: 15px; margin-bottom: 8px; border-bottom: 1px solid #444; padding-bottom: 4px; }
        .sidebar-menu-item { display: block; color: #fff; text-decoration: none; padding: 6px 10px; border-radius: 4px; font-size: 0.9rem; margin-bottom: 3px; }
        .sidebar-menu-item:hover { background-color: #333; color: #ffc107; }
        .content-area { flex-grow: 1; background-color: #ffffff; padding: 20px; box-shadow: inset 0 0 10px rgba(0,0,0,0.05); }
        .countdown-badge { background-color: #ffc107; color: #000; padding: 3px 10px; border-radius: 4px; font-weight: bold; font-family: monospace; }
    </style>
    <script>
        function updateClock() {
            const now = new Date();
            const hours = String(now.getHours()).padStart(2, '0');
            const minutes = String(now.getMinutes()).padStart(2, '0');
            const seconds = String(now.getSeconds()).padStart(2, '0');
            const day = String(now.getDate()).padStart(2, '0');
            const month = String(now.getMonth() + 1).padStart(2, '0');
            const year = now.getFullYear();
            document.getElementById('live-clock').innerText = `${day}/${month}/${year} ${hours}:${minutes}:${seconds}`;
        }
        setInterval(updateClock, 1000);
        window.onload = updateClock;

        function startCountdown(targetTimeStr) {
            if (!targetTimeStr) return;
            const targetTime = new Date(targetTimeStr).getTime();
            function timer() {
                const now = new Date().getTime();
                const distance = targetTime - now;
                const el = document.getElementById('countdown-timer');
                if (!el) return;
                if (distance < 0) {
                    el.innerHTML = "🔴 ปิดรับแทงแล้ว / รอผล";
                    el.className = "badge bg-warning text-dark px-2 py-1";
                    return;
                }
                const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((distance % (1000 * 60)) / 1000);
                el.innerHTML = `⏱️ เหลือเวลาเปิดรับ: ${hours}ชม. ${minutes}น. ${seconds}วิ.`;
            }
            setInterval(timer, 1000);
            timer();
        }
    </script>
</head>
<body>
    <div class="top-navbar">
        <div class="fw-bold fs-5 text-warning">
            Lotto ERP | งวด: <span class="text-white">{{ draw_date }}</span> | User: <b>{{ username }} ({{ role }})</b>
        </div>
        <div class="top-nav-links">
            <a href="/dashboard?user={{ username }}&draw={{ draw_date }}">📊 แดชบอร์ด</a>
            <a href="/buy?user={{ username }}&draw={{ draw_date }}">🛒 บันทึกโพย</a>
            {% if role == 'Admin' %}
            <a href="/audit-all?user={{ username }}&draw={{ draw_date }}">🔍 ตรวจสอบทั้งหมด</a>
            <a href="/results?user={{ username }}&draw={{ draw_date }}">🏆 ออกผลรางวัล</a>
            <a href="/db-inspector?user={{ username }}&draw={{ draw_date }}">🗄️ ตรวจสอบ DB</a>
            {% endif %}
            <a href="/password?user={{ username }}&draw={{ draw_date }}">⚙ ตั้งค่าเริ่มต้น</a>
            <a href="/customers?user={{ username }}&draw={{ draw_date }}">👥 จัดการลูกค้า</a>
        </div>
        <div class="d-flex align-items-center gap-3">
            <span id="live-clock" class="text-info fw-bold font-monospace">กำลังโหลด...</span>
            <a href="/logout" class="btn btn-danger btn-sm fw-bold px-3">🚪 ออกจากระบบ</a>
        </div>
    </div>

    <div class="ticker-banner">
        <span>📢 งวดที่กำลังทำงาน: {{ draw_date }}</span>
        {% if current_close_time %}
        <span id="countdown-timer" class="countdown-badge">กำลังโหลดเวลา...</span>
        <script>startCountdown("{{ current_close_time }}");</script>
        {% endif %}
    </div>

    <div class="main-wrapper">
        <div class="sidebar">
            <div class="user-profile-box">
                <div class="text-warning fw-bold fs-5">👤 ยินดีต้อนรับ</div>
                <div class="text-white fw-bold fs-6 mt-1">{{ username }}</div>
                <div class="text-info small">({{ role }})</div>
            </div>

            <div class="sidebar-section-title">จัดการผู้ใช้</div>
            {% if role == 'Admin' %}
                <a href="/users?user={{ username }}&draw={{ draw_date }}" class="sidebar-menu-item">▶ Master</a>
                <a href="/users?user={{ username }}&draw={{ draw_date }}" class="sidebar-menu-item">▶ เอเย่นต์</a>
                <a href="/users?user={{ username }}&draw={{ draw_date }}" class="sidebar-menu-item">▶ สมาชิก</a>
            {% elif role == 'Master Agent' %}
                <a href="/users?user={{ username }}&draw={{ draw_date }}" class="sidebar-menu-item">▶ เอเย่นต์</a>
                <a href="/users?user={{ username }}&draw={{ draw_date }}" class="sidebar-menu-item">▶ สมาชิก</a>
            {% elif role == 'Agent' %}
                <a href="/users?user={{ username }}&draw={{ draw_date }}" class="sidebar-menu-item">▶ สมาชิก</a>
            {% endif %}

            <div class="sidebar-section-title">ตั้งค่าเรตพิเศษ</div>
            <a href="/customer-rates-page?user={{ username }}" class="sidebar-menu-item text-warning fw-bold">
                ⚙️ เรตลูกค้าแยกตามหวย
            </a>

<!-- นำปุ่มนี้ไปแทรกไว้ในหน้าเมนูหรือหน้าเลือกตลาดของ Admin -->
            <a href="/system-reset?user={{ username }}" class="btn btn-outline-danger btn-sm fw-bold">
                ⚠️ รีเซ็ตระบบ (Go-Live)
            </a>

            <div class="sidebar-section-title">แทงหวย</div>
            <a href="/campaigns?user={{ username }}" class="sidebar-menu-item text-warning fw-bold">▶ จัดการและเลือกงวดหวย</a>
            {% if role == 'Admin' %}
            <a href="/blocked-numbers?user={{ username }}&draw={{ draw_date }}" class="sidebar-menu-item">🚫 จัดการเลขอั้น</a>
            {% endif %}

            <div class="sidebar-section-title">รายงานและเครื่องมือ</div>
            <a href="/results?user={{ username }}&draw={{ draw_date }}" class="sidebar-menu-item">▶ ชนะ แพ้ (รายละเอียด)</a>
            <a href="/reports?user={{ username }}&draw={{ draw_date }}" class="sidebar-menu-item">▶ รายงานยอดขาย</a>
            <a href="/audit-discount?user={{ username }}&draw={{ draw_date }}" class="sidebar-menu-item">🔍 ตรวจสอบส่วนลดลูกค้า</a>
        </div>

        <div class="content-area">
            {% if msg %}
                <div class="alert alert-success text-center fw-bold">{{ msg }}</div>
            {% endif %}
            {% if error %}
                <div class="alert alert-danger text-center fw-bold" style="font-size: 1.1rem; border: 2px solid #dc3545;">⚠️ {{ error }}</div>
            {% endif %}
            {{ content | safe }}
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Lotto ERP Cloud</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark d-flex align-items-center justify-content-center" style="height: 100vh;">
    <div class="card bg-white p-4 shadow border border-warning" style="width: 380px;">
        <h3 class="text-center text-primary mb-4 fw-bold">☁ Lotto ERP Cloud</h3>
        {% if error %}
            <div class="alert alert-danger py-2 text-center">{{ error }}</div>
        {% endif %}
        <form method="POST" action="/login">
            <div class="mb-3">
                <label class="form-label fw-bold text-dark">ชื่อผู้ใช้งาน (Username)</label>
                <input type="text" name="username" class="form-control" required autofocus>
            </div>
            <div class="mb-3">
                <label class="form-label fw-bold text-dark">รหัสผ่าน (Password)</label>
                <input type="password" name="password" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-warning w-100 fw-bold py-2 text-dark">เข้าสู่ระบบ</button>
        </form>
    </div>
</body>
</html>
"""

# ================= 8. หน้าจอและฟังก์ชันรีเซ็ตระบบ (Factory Reset สำหรับ Admin) =================
SYSTEM_RESET_TEMPLATE = """
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <title>LuckyNumber - System Reset (Go-Live)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-danger-subtle d-flex align-items-center justify-content-center" style="height: 100vh;">
    <div class="card shadow-lg p-5 border border-danger border-3 bg-white" style="max-width: 600px; width: 100%;">
        <div class="text-center mb-4">
            <i class="fa-solid fa-triangle-exclamation text-danger fa-4x mb-3"></i>
            <h2 class="text-danger fw-bold">⚠️ พื้นที่อันตราย: รีเซ็ตระบบเพื่อใช้งานจริง (Factory Reset)</h2>
            <p class="text-muted small mt-2">คำสั่งนี้จะล้างข้อมูลการทดสอบทั้งหมดในฐานข้อมูลออกอย่างถาวร (โพย, ลูกค้า, สมาชิกทดสอบ, เลขอั้น, เรต, และงวดหวย) เพื่อให้ระบบสะอาดพร้อมเริ่มต้นใช้งานจริง</p>
        </div>

        {% if error %}
        <div class="alert alert-danger text-center fw-bold">{{ error }}</div>
        {% endif %}

        <form method="POST" action="/execute-system-reset" onsubmit="return confirm('⚠️ คำเตือนขั้นเด็ดขาด! คุณแน่ใจจริงๆ หรือไม่ที่จะล้างข้อมูลทั้งหมดในระบบออก? ข้อมูลที่ถูกลบจะไม่สามารถกู้คืนได้!');">
            <input type="hidden" name="username" value="{{ username }}">
            
            <div class="mb-3">
                <label class="form-label fw-bold text-dark">🔑 ยืนยันรหัสผ่าน Admin ของคุณ:</label>
                <input type="password" name="admin_password" class="form-control form-control-lg" placeholder="กรอกรหัสผ่านเพื่อยืนยัน..." required autofocus>
            </div>

            <div class="d-grid gap-2 mt-4">
                <button type="submit" class="btn btn-danger btn-lg fw-bold py-3">
                    <i class="fa-solid fa-bomb"></i> ยืนยันล้างข้อมูลและรีเซ็ตระบบทั้งหมด
                </button>
                <a href="/select-market?user={{ username }}" class="btn btn-outline-secondary btn-lg fw-bold py-2">
                    ❌ ยกเลิกและกลับสู่หน้าหลัก
                </a>
            </div>
        </form>
    </div>
</body>
</html>
"""

@app.get("/system-reset", response_class=HTMLResponse)
def system_reset_page(user: str, error: str = None):
    try:
        conn = connect_db()
        c = conn.cursor()
        # ตรวจสอบสิทธิ์ว่าเป็น Admin จริงหรือไม่
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        res = c.fetchone()
        conn.close()
        
        role = res[0] if res else ""
        if role != 'Admin':
            return RedirectResponse(url=f"/select-market?user={user}", status_code=303)
    except:
        return RedirectResponse(url=f"/select-market?user={user}", status_code=303)

    return Template(SYSTEM_RESET_TEMPLATE).render(username=user, error=error)

@app.post("/execute-system-reset")
def execute_system_reset(username: str = Form(...), admin_password: str = Form(...)):
    try:
        conn = connect_db()
        c = conn.cursor()
        
        # 1. ตรวจสอบรหัสผ่านของ Admin เพื่อความปลอดภัยสูงสุด
        c.execute("SELECT id FROM Users WHERE username=%s AND password=%s AND role='Admin'", (username, admin_password))
        admin_check = c.fetchone()
        
        if not admin_check:
            conn.close()
            return RedirectResponse(url=f"/system-reset?user={username}&error=รหัสผ่าน Admin ไม่ถูกต้อง ไม่สามารถรีเซ็ตระบบได้!", status_code=303)

        # 2. ทำการเคลียร์ข้อมูลในตารางต่างๆ ออกทั้งหมด
        c.execute("DELETE FROM Transactions;")
        c.execute("DELETE FROM TempDraft;")
        c.execute("DELETE FROM BlockedNumbers;")
        c.execute("DELETE FROM CustomerLottoRates;")
        c.execute("DELETE FROM AgentSettlements;")
        c.execute("DELETE FROM DrawResults;")
        c.execute("DELETE FROM Customers;")
        c.execute("DELETE FROM LotteryCampaigns;")
        
        # 3. ลบ Users ทั้งหมด ยกเว้นบัญชี Admin ปัจจุบัน
        c.execute("DELETE FROM Users WHERE username != %s;", (username,))
        
        conn.commit()
        conn.close()
        
        # รีเซ็ตสำเร็จ เด้งกลับไปหน้า Login พร้อมข้อความ
        return RedirectResponse(url="/login?error=รีเซ็ตระบบสำเร็จ! ข้อมูลถูกล้างเกลี้ยงพร้อมเริ่มใช้งานจริงแล้ว กรุณาเข้าสู่ระบบใหม่อีกครั้ง", status_code=303)
        
    except Exception as e:
        return RedirectResponse(url=f"/system-reset?user={username}&error=เกิดข้อผิดพลาดในการรีเซ็ต: {str(e)}", status_code=303)

CAMPAIGN_TEMPLATE = """
<div class="container my-3" style="max-width: 900px;">
    {% if missing_close_time_campaigns %}
    <div class="alert alert-danger border border-danger shadow p-3 mb-4 rounded">
        <h5 class="fw-bold text-danger"><i class="fa-solid fa-triangle-exclamation"></i> แจ้งเตือนสำคัญ: พบงวดหวยที่ยังไม่ได้กำหนด "เวลาปิดรับ" จำนวน {{ missing_close_time_campaigns | length }} งวด</h5>
        <ul class="mb-0 fw-bold text-danger">
            {% for mc in missing_close_time_campaigns %}
                <li>งวด: {{ mc['draw_date'] }} (ID: {{ mc['id'] }}) — <a href="/campaigns?user={{ username }}&edit_id={{ mc['id'] }}" class="btn btn-sm btn-outline-danger py-0 fw-bold">แก้ไขด่วนที่นี่</a></li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}

    <div class="card bg-white p-4 shadow border mb-4">
        <h2 class="text-center text-primary mb-4 fw-bold">📌 จัดการและเลือกงวดหวย</h2>
        
        {% if role == 'Admin' %}
            {% if edit_campaign %}
            <div class="card bg-warning-subtle p-3 mb-4 border border-warning">
                <h5 class="text-dark mb-3 fw-bold">✏️ แก้ไขงวดหวยและเวลาปิดรับ</h5>
                <form method="POST" action="/update-campaign">
                    <input type="hidden" name="user" value="{{ username }}">
                    <input type="hidden" name="campaign_id" value="{{ edit_campaign[3] }}">
                    <div class="mb-2">
                        <label class="form-label fw-bold text-dark">ชื่อหวย:</label>
                        <input type="text" name="lotto_name" class="form-control" value="{{ edit_campaign[0] }}" required>
                    </div>
                    <div class="mb-2">
                        <label class="form-label fw-bold text-dark">งวดวันที่:</label>
                        <input type="text" name="draw_date" class="form-control" value="{{ edit_campaign[1] }}" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label fw-bold text-danger">⏰ เวลาปิดรับแทง (บังคับระบุ):</label>
                        <input type="datetime-local" name="close_time" class="form-control" value="{{ edit_campaign[4] }}" required>
                    </div>
                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-warning w-100 fw-bold py-2">💾 บันทึกการแก้ไข</button>
                        <a href="/campaigns?user={{ username }}" class="btn btn-outline-dark w-100 fw-bold py-2">ยกเลิก</a>
                    </div>
                </form>
            </div>
            {% else %}
            <div class="card bg-light p-3 mb-4 border border-primary">
                <h5 class="text-primary mb-3 fw-bold">➕ เปิดงวดหวยใหม่ (Admin)</h5>
                <form method="POST" action="/create-campaign">
                    <input type="hidden" name="user" value="{{ username }}">
                    <div class="mb-2">
                        <label class="form-label fw-bold text-dark">ชื่อหวย:</label>
                        <input type="text" name="lotto_name" class="form-control" placeholder="เช่น หวยรัฐบาล, หวยลาว" required>
                    </div>
                    <div class="mb-2">
                        <label class="form-label fw-bold text-dark">งวดวันที่:</label>
                        <input type="text" name="draw_date" class="form-control" placeholder="เช่น 16 ตุลาคม 2026" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label fw-bold text-danger">⏰ เวลาปิดรับแทง (บังคับระบุ):</label>
                        <input type="datetime-local" name="close_time" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100 fw-bold py-2">เปิดงวดใหม่พร้อมเวลาปิดรับ</button>
                </form>
            </div>
            {% endif %}
        {% endif %}
        
        <ul class="nav nav-tabs fw-bold mb-3" id="campaignTab" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active text-primary" id="active-tab" data-bs-toggle="tab" data-bs-target="#active" type="button" role="tab" aria-controls="active" aria-selected="true">
                    🟢 งวดที่กำลังเปิด และ รอผลรางวัล
                </button>
            </li>
            {% if role == 'Admin' %}
            <li class="nav-item" role="presentation">
                <button class="nav-link text-secondary" id="history-tab" data-bs-toggle="tab" data-bs-target="#history" type="button" role="tab" aria-controls="history" aria-selected="false">
                    📁 งวดที่ปิดแล้ว (ประวัติย้อนหลัง)
                </button>
            </li>
            {% endif %}
        </ul>

        <div class="tab-content" id="campaignTabContent">
            <div class="tab-pane fade show active" id="active" role="tabpanel" aria-labelledby="active-tab">
                <div class="list-group">
                    {% for camp in active_campaigns %}
                        {% set l_name = camp['lotto_name'] %}
                        {% if 'รัฐบาล' in l_name or 'ไทย' in l_name %} {% set img_url = 'https://upload.wikimedia.org/wikipedia/commons/thumb/a/a9/Flag_of_Thailand.svg/1024px-Flag_of_Thailand.svg.png' %}
                        {% elif 'ลาว' in l_name %} {% set img_url = 'https://upload.wikimedia.org/wikipedia/commons/thumb/5/56/Flag_of_Laos.svg/1024px-Flag_of_Laos.svg.png' %}
                        {% elif 'ฮานอย' in l_name or 'เวียดนาม' in l_name %} {% set img_url = 'https://upload.wikimedia.org/wikipedia/commons/thumb/2/21/Flag_of_Vietnam.svg/1024px-Flag_of_Vietnam.svg.png' %}
                        {% elif 'มาเลย์' in l_name %} {% set img_url = 'https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/Flag_of_Malaysia.svg/1024px-Flag_of_Malaysia.svg.png' %}
                        {% elif 'หุ้น' in l_name %} {% set img_url = 'https://cdn-icons-png.flaticon.com/512/3061/3061292.png' %}
                        {% elif 'ยี่กี' in l_name or 'ปิงปอง' in l_name %} {% set img_url = 'https://cdn-icons-png.flaticon.com/512/868/868776.png' %}
                        {% else %} {% set img_url = 'https://cdn-icons-png.flaticon.com/512/5359/5359877.png' %}
                        {% endif %}

                        <div class="list-group-item list-group-item-light py-3 mb-2 d-flex justify-content-between align-items-center border shadow-sm rounded {% if not camp['close_time'] %}border-danger bg-danger-subtle{% endif %}">
                            <div class="d-flex align-items-center">
                                <div class="me-3 shadow-sm rounded-circle overflow-hidden bg-white border border-warning d-flex align-items-center justify-content-center" style="width: 60px; height: 60px; flex-shrink: 0;">
                                    <img src="{{ img_url }}" alt="lotto-logo" style="width: 100%; height: 100%; object-fit: cover;">
                                </div>
                                <div>
                                    <a href="/buy?user={{ username }}&draw={{ camp['lotto_name'] }} งวด {{ camp['draw_date'] }}" class="text-primary text-decoration-none fs-5 fw-bold">
                                        {{ camp['lotto_name'] }} งวดวันที่ {{ camp['draw_date'] }}
                                    </a>
                                    <div class="small text-muted mt-1">
                                        สถานะ: 
                                        {% if camp['status'] == 'รอผลรางวัล' %}
                                            <span class="badge bg-warning text-dark">{{ camp['status'] }}</span>
                                        {% elif camp['status'] == 'เปิดรับแทง' %}
                                            <span class="badge bg-success">{{ camp['status'] }}</span>
                                        {% else %}
                                            <span class="badge bg-secondary">{{ camp['status'] }}</span>
                                        {% endif %}
                                        | ⏰ ปิดรับ: <b class="text-danger">{{ camp['close_time']|replace("T", " ") if camp['close_time'] else '⚠️ ยังไม่ได้ระบุ' }}</b>
                                    </div>
                                </div>
                            </div>
                            {% if role == 'Admin' %}
                            <div class="d-flex flex-column gap-2">
                                <a href="/campaigns?user={{ username }}&edit_id={{ camp['id'] }}" class="btn btn-warning btn-sm fw-bold">✏️ แก้ไข</a>
                                <a href="/toggle-campaign?id={{ camp['id'] }}&user={{ username }}" class="btn btn-outline-dark btn-sm fw-bold">สลับปิด-เปิด</a>
                            </div>
                            {% endif %}
                        </div>
                    {% else %}
                        <div class="text-center text-muted py-4">ไม่มีงวดที่กำลังเปิดรับแทงหรือรอผล</div>
                    {% endfor %}
                </div>
            </div>

            {% if role == 'Admin' %}
            <div class="tab-pane fade" id="history" role="tabpanel" aria-labelledby="history-tab">
                <div class="list-group">
                    {% for camp in closed_campaigns %}
                        <div class="list-group-item bg-light text-muted py-3 mb-2 d-flex justify-content-between align-items-center border shadow-sm rounded">
                            <div class="d-flex align-items-center opacity-75">
                                <div class="fs-1 me-3 text-secondary"><i class="fa-solid fa-box-archive"></i></div>
                                <div>
                                    <a href="/buy?user={{ username }}&draw={{ camp['lotto_name'] }} งวด {{ camp['draw_date'] }}" class="text-secondary text-decoration-none fs-5 fw-bold">
                                        {{ camp['lotto_name'] }} งวดวันที่ {{ camp['draw_date'] }}
                                    </a>
                                    <div class="small mt-1">
                                        สถานะ: <span class="badge bg-secondary">{{ camp['status'] }}</span> | 
                                        ออกผลแล้วเมื่อ: <b>{{ camp['result_time'] }}</b>
                                    </div>
                                </div>
                            </div>
                            <div class="d-flex flex-column gap-2">
                                <a href="/campaigns?user={{ username }}&edit_id={{ camp['id'] }}" class="btn btn-outline-secondary btn-sm fw-bold">✏️ แก้ไข</a>
                                <a href="/toggle-campaign?id={{ camp['id'] }}&user={{ username }}" class="btn btn-outline-dark btn-sm fw-bold">เปิดใช้งานอีกครั้ง</a>
                            </div>
                        </div>
                    {% else %}
                        <div class="text-center text-muted py-4">ยังไม่มีประวัติงวดที่ปิดแล้วเกิน 2 วัน</div>
                    {% endfor %}
                </div>
            </div>
            {% endif %}
        </div>
    </div>
</div>
"""

BLOCKED_TEMPLATE = """
<div class="row">
    <div class="col-md-5 mb-4">
        <div class="card shadow p-4">
            {% if edit_blocked %}
                <h4 class="text-warning mb-3 fw-bold">✏️ แก้ไขเลขอั้น</h4>
                <form method="POST" action="/update-blocked">
                    <input type="hidden" name="user" value="{{ username }}">
                    <input type="hidden" name="draw" value="{{ draw_date }}">
                    <input type="hidden" name="blocked_id" value="{{ edit_blocked[0] }}">
                    <div class="mb-3"><label class="form-label fw-bold">หมายเลขเลขอั้น:</label><input type="text" name="raw_num" class="form-control" value="{{ edit_blocked[2] }}" required></div>
                    <div class="mb-3"><label class="form-label fw-bold">สถานะ:</label><select name="status" class="form-select"><option value="ปิดรับ" {% if edit_blocked[3] == 'ปิดรับ' %}selected{% endif %}>ปิดรับ</option><option value="จ่ายครึ่ง" {% if edit_blocked[3] == 'จ่ายครึ่ง' %}selected{% endif %}>จ่ายครึ่ง</option></select></div>
                    <button type="submit" class="btn btn-warning w-100 fw-bold mb-2">💾 บันทึก</button>
                    <a href="/blocked-numbers?user={{ username }}&draw={{ draw_date }}" class="btn btn-outline-secondary w-100 fw-bold">ยกเลิก</a>
                </form>
            {% else %}
                <h4 class="text-danger mb-3 fw-bold">🚫 นำเข้าเลขอั้น</h4>
                <form method="POST" action="/save-blocked">
                    <input type="hidden" name="user" value="{{ username }}">
                    <input type="hidden" name="draw" value="{{ draw_date }}">
                    <div class="mb-3"><label class="form-label fw-bold">ข้อมูลดิบ (ใช้คอมม่าคั่น):</label><textarea name="raw_input" class="form-control" rows="5" required autofocus></textarea></div>
                    <div class="mb-3"><label class="form-label fw-bold">สถานะ:</label><select name="status" class="form-select"><option value="ปิดรับ">ปิดรับ</option><option value="จ่ายครึ่ง">จ่ายครึ่ง</option></select></div>
                    <button type="submit" class="btn btn-danger w-100 fw-bold py-2">💾 ประมวลผลเลขอั้น</button>
                </form>
            {% endif %}
        </div>
    </div>
    <div class="col-md-7">
        <div class="card shadow p-4">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h4 class="text-primary mb-0 fw-bold">📋 รายการเลขอั้นงวดนี้</h4>
                {% if blocked_list %}
                <a href="/clear-blocked?user={{ username }}&draw={{ draw_date }}" class="btn btn-outline-danger btn-sm fw-bold" onclick="return confirm('⚠️ ล้างข้อมูลทั้งหมด?')">🗑️ ล้างข้อมูลเลขอั้น</a>
                {% endif %}
            </div>
            <div class="table-responsive" style="max-height: 500px; overflow-y: auto;">
                <table class="table table-striped table-bordered text-center align-middle" style="font-size: 0.9rem;">
                    <thead class="table-dark sticky-top">
                        <tr><th>ID</th><th>หมายเลข</th><th>สถานะ</th><th>ประเภท</th><th>จัดการ</th></tr>
                    </thead>
                    <tbody>
                        {% for b in blocked_list %}
                        <tr>
                            <td>{{ b[0] }}</td><td><b class="text-danger fs-6">{{ b[2] }}</b></td><td><span class="badge {% if b[3] == 'ปิดรับ' %}bg-danger{% else %}bg-warning text-dark{% endif %}">{{ b[3] }}</span></td><td>{{ b[4] }}</td>
                            <td><a href="/blocked-numbers?user={{ username }}&draw={{ draw_date }}&edit_id={{ b[0] }}" class="btn btn-warning btn-sm py-0 px-1 fw-bold">✏️</a> <a href="/delete-blocked?id={{ b[0] }}&user={{ username }}&draw={{ draw_date }}" class="btn btn-outline-danger btn-sm py-0 px-1 fw-bold">🗑️</a></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
"""

BUY_CONTENT = """
<div class="row">
    <div class="col-lg-8">
        <div class="card shadow p-4 mb-4">
            <form id="custForm" method="GET" action="/buy">
                <input type="hidden" name="user" value="{{ username }}">
                <input type="hidden" name="draw" value="{{ draw_date }}">
                <div class="mb-3">
                    <label class="form-label fw-bold text-dark">เลือกลูกค้า / สายงาน:</label>
                    <select name="selected" id="customerSelect" class="form-select form-select-lg" onchange="document.getElementById('custForm').submit()">
                        {% for c in customers %}
                            <option value="{{ c[0] }}|{{ c[1] }}|{{ c[2] }}" {% if selected_target_raw and selected_target_raw == c[0]|string ~ '|' ~ c[1] ~ '|' ~ c[2] %}selected{% endif %}>{{ c[1] }} ({{ c[2] }})</option>
                        {% endfor %}
                    </select>
                </div>
            </form>

            <form method="POST" action="/add-draft">
                <input type="hidden" name="user" value="{{ username }}">
                <input type="hidden" name="draw" value="{{ draw_date }}">
                <input type="hidden" name="customer_info" value="{{ selected_target_raw }}">
                
                <div class="mb-2">
                    <label class="form-label fw-bold text-dark mb-1">เลข &nbsp;=&nbsp; บน/วิ่งบน &nbsp;&times;&nbsp; โต๊ด/ล่าง/วิ่งล่าง</label>
                    <div class="row g-2 align-items-center mb-2">
                        <div class="col-md-3"><input type="text" name="col_num" class="form-control" placeholder="พิมพ์เลข..."></div>
                        <div class="col-auto fw-bold fs-5 text-dark">=</div>
                        <div class="col-md-4"><input type="number" step="any" name="col_teng" class="form-control" placeholder="ยอดเงิน (บน)"></div>
                        <div class="col-auto fw-bold fs-5 text-dark">&times;</div>
                        <div class="col-md-4"><input type="number" step="any" name="col_tod" class="form-control" placeholder="ยอดเงิน (ล่าง)"></div>
                    </div>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-bold text-dark small">คีย์ต่อเนื่อง ใช้ "," คั่น (รวดเร็วไม่หน่วง)</label>
                    <input type="text" name="raw_input" class="form-control" placeholder="พิมพ์เลขและราคา...">
                </div>
                <button type="submit" class="btn btn-success btn-lg w-100 fw-bold"><i class="fa-solid fa-cart-plus"></i> บันทึกลงรายการร่าง</button>
            </form>
        </div>

        <div class="card shadow p-4 mb-4">
            <h4 class="text-primary mb-3 fw-bold">📋 1. รายการร่าง (รอยืนยันโพย)</h4>
            <div class="table-responsive">
                <table class="table table-striped table-bordered text-center align-middle">
                    <thead class="table-dark">
                        <tr><th>เลข</th><th>ประเภท</th><th>ยอดซื้อ</th><th>อัตราจ่าย</th><th>ส่วนลด</th><th>ยอดสุทธิ</th><th>สถานะอั้น</th><th>จัดการ</th></tr>
                    </thead>
                    <tbody>
                        {% for d in drafts %}
                        <tr>
                            <td><b>{{ d[1] }}</b></td><td>{{ d[4] }}</td><td>{{ "{:,.2f}".format(d[2] | float) }}</td><td><span class="badge bg-success">{{ d[5] }}</span></td>
                            <td class="text-danger">{{ "{:,.2f}".format(d[6] | float) }}</td><td class="text-success fw-bold">{{ "{:,.2f}".format(d[7] | float) }}</td>
                            <td><span class="badge {% if d[3] == 'ปกติ' %}bg-danger{% else %}bg-warning text-dark{% endif %}">{{ d[3] }}</span></td>
                            <td>
                                <a href="/edit-draft-item?id={{ d[0] }}&user={{ username }}&draw={{ draw_date }}&selected={{ selected_target_raw }}" class="text-decoration-none fw-bold me-1">แก้ไข</a>
                                <a href="/delete-draft-item?id={{ d[0] }}&user={{ username }}&draw={{ draw_date }}&selected={{ selected_target_raw }}" class="text-danger text-decoration-none fw-bold">ลบ</a>
                            </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="8" class="text-muted">ยังไม่มีรายการในร่าง</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

            {% if drafts %}
            <div class="card bg-light p-3 mb-3 border">
                <div class="row text-center fw-bold text-dark">
                    <div class="col">ยอดซื้อรวม: ฿{{ "{:,.2f}".format(draft_totals.sum_amt) }}</div>
                    <div class="col text-danger">ส่วนลดรวม: ฿{{ "{:,.2f}".format(draft_totals.sum_disc) }}</div>
                    <div class="col text-primary">ยอดสุทธิที่ต้องชำระ: ฿{{ "{:,.2f}".format(draft_totals.sum_net) }}</div>
                </div>
            </div>
            
            <div class="row g-2">
                <div class="col-md-6">
                    <button type="button" class="btn btn-primary btn-lg w-100 fw-bold" data-bs-toggle="modal" data-bs-target="#billModal"><i class="fa-solid fa-check"></i> ยืนยันโพย (เปิดหน้าต่างบิล)</button>
                </div>
                <div class="col-md-6">
                    <a href="/clear-draft?user={{ username }}&draw={{ draw_date }}&selected={{ selected_target_raw }}" class="btn btn-outline-danger btn-lg w-100 fw-bold">ยกเลิกรายการร่างทั้งหมด</a>
                </div>
            </div>
            {% endif %}
        </div>
    </div>

    <div class="col-lg-4">
        <div class="card shadow p-3 bg-white mb-4 border">
            <label class="fw-bold text-dark mb-1">เลขอั้นปิดรับ:</label><textarea class="form-control mb-3 bg-light text-danger fw-bold" rows="3" readonly>{{ block_closed }}</textarea>
            <label class="fw-bold text-dark mb-1">เลขอั้น 3ตัว (จ่ายครึ่ง):</label><textarea class="form-control mb-3 bg-light text-dark" rows="3" readonly>{{ block_3d }}</textarea>
            <label class="fw-bold text-dark mb-1">เลขอั้น 2ตัว (จ่ายครึ่ง):</label><textarea class="form-control bg-light text-dark" rows="3" readonly>{{ block_2d }}</textarea>
        </div>

        <div class="card shadow p-3 bg-white mb-4 border">
            <h5 class="text-center fw-bold mb-3">รายการล่าสุด</h5>
            <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                <table class="table table-sm table-bordered text-center align-middle" style="font-size: 0.8rem;">
                    <thead class="table-dark">
                        <tr><th>TIME</th><th>บิล</th><th>เลข</th><th>ยอดซื้อ</th></tr>
                    </thead>
                    <tbody>
                        {% for tx in recent_transactions %}
                        <tr>
                            <td><small>{{ tx[2][-8:] }}</small></td>
                            <td><code>{{ tx[7] }}</code></td>
                            <td><b>{{ tx[8] }}</b></td>
                            <td>{{ "{:,.0f}".format(tx[10] | float) }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="billModal" tabindex="-1" aria-labelledby="billModalLabel" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
    <div class="modal-content border border-warning shadow-lg">
      <div class="modal-header bg-dark text-white">
        <h5 class="modal-title fw-bold text-warning" id="billModalLabel"><i class="fa-solid fa-receipt"></i> ตรวจสอบรายละเอียดบิล</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body p-4 bg-white">
        <div class="card p-3 mb-3 bg-light border-secondary border-2" style="border-style: dashed !important;">
            <div class="row text-start text-dark" style="font-size: 0.95rem;">
                <div class="col-12 mb-1"><strong>เลขที่บิล:</strong> <span class="text-primary fw-bold">{{ preview_bill_no }}</span></div>
                <div class="col-12 mb-1"><strong>วันที่ทำรายการ:</strong> {{ preview_time }}</div>
                <div class="col-12 mb-1"><strong>งวดหวย:</strong> {{ lotto_name_for_bill }} <span class="text-muted">(งวด: {{ draw_date_clean }})</span></div>
                <div class="col-12"><strong>ลูกค้า:</strong> {{ customer_name_for_bill }}</div>
            </div>
        </div>
        <table class="table table-sm table-bordered text-center align-middle" style="font-size: 0.9rem;">
            <thead class="table-secondary">
                <tr><th>หมายเลข</th><th>ประเภท</th><th>ยอดซื้อ</th><th>สุทธิ</th></tr>
            </thead>
            <tbody>
                {% for d in drafts %}
                <tr>
                    <td><b>{{ d[1] }}</b></td><td>{{ d[4] }}</td><td>{{ "{:,.0f}".format(d[2] | float) }}</td><td class="fw-bold text-success">{{ "{:,.0f}".format(d[7] | float) }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        <div class="card bg-white p-2 mt-2 border">
            <div class="d-flex justify-content-between"><span class="text-muted">ยอดรวม:</span> <b>฿{{ "{:,.2f}".format(draft_totals.sum_amt) }}</b></div>
            <div class="d-flex justify-content-between"><span class="text-danger">ส่วนลด:</span> <b class="text-danger">฿{{ "{:,.2f}".format(draft_totals.sum_disc) }}</b></div>
            <hr class="my-1">
            <div class="d-flex justify-content-between fs-5"><span class="text-primary fw-bold">ยอดสุทธิ:</span> <b class="text-primary">฿{{ "{:,.2f}".format(draft_totals.sum_net) }}</b></div>
        </div>
      </div>
      <div class="modal-footer d-flex justify-content-between bg-dark">
        <button type="button" class="btn btn-outline-light fw-bold" data-bs-dismiss="modal">❌ กลับไปแก้ไข</button>
        <form method="POST" action="/confirm-bill">
            <input type="hidden" name="user" value="{{ username }}">
            <input type="hidden" name="draw" value="{{ draw_date }}">
            <input type="hidden" name="customer_info" value="{{ selected_target_raw }}">
            <input type="hidden" name="lotto_name" value="{{ lotto_name_for_bill }}">
            <button type="submit" class="btn btn-warning fw-bold px-4">💾 ยืนยันและพิมพ์บิล</button>
        </form>
      </div>
    </div>
  </div>
</div>
"""

BILL_PRINT_TEMPLATE = """
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>พิมพ์สลิปบิล</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .slip-container { max-width: 320px; margin: 20px auto; background: #fff; padding: 15px; border: 1px dashed #ccc; box-shadow: 0 0 10px rgba(0,0,0,0.1); font-family: 'Courier New', Courier, monospace; }
        .text-center { text-align: center; }
        .fw-bold { font-weight: bold; }
        .dashed-line { border-top: 1px dashed #000; margin: 10px 0; }
        .table-slip { width: 100%; font-size: 0.85rem; margin-bottom: 10px;}
        .table-slip th, .table-slip td { padding: 2px 0; }
        .table-slip th { border-bottom: 1px dashed #000; }
        .btn-print { width: 100%; font-weight: bold; margin-bottom: 10px; font-family: sans-serif; }
        @media print {
            body { background: none; }
            .slip-container { box-shadow: none; border: none; margin: 0; padding: 0; }
            .no-print { display: none !important; }
        }
    </style>
</head>
<body>
    <div class="slip-container">
        <div class="text-center fw-bold fs-5">{{ lotto_title }}</div>
        <div class="text-center small">งวดวันที่: {{ draw_date }}</div>
        <div class="text-center small mt-1">ผู้ซื้อ: {{ customer_name }}</div>
        <div class="text-center small">แคชเชียร์: {{ username }}</div>
        <div class="text-center fw-bold mt-2">{{ bill_no }}</div>
        <div class="text-center small">{{ timestamp }}</div>
        
        <div class="dashed-line"></div>
        <table class="table-slip">
            <thead>
                <tr><th style="text-align:left;">เลข</th><th style="text-align:left;">ประเภท</th><th style="text-align:right;">ราคา</th></tr>
            </thead>
            <tbody>
                {% for item in bill_items %}
                <tr>
                    <td style="text-align:left;" class="fw-bold">{{ item.num }}</td>
                    <td style="text-align:left;">{{ item.type }}</td>
                    <td style="text-align:right;">{{ "{:,.0f}".format(item.amount) }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        <div class="dashed-line"></div>
        
        <div style="display: flex; justify-content: space-between; font-size: 0.85rem;">
            <span>ยอดรวม:</span> <span>{{ "{:,.2f}".format(total_amt) }}</span>
        </div>
        <div style="display: flex; justify-content: space-between; font-size: 0.85rem;">
            <span>ส่วนลด:</span> <span>-{{ "{:,.2f}".format(total_disc) }}</span>
        </div>
        <div class="dashed-line"></div>
        <div style="display: flex; justify-content: space-between; font-size: 1.1rem; font-weight: bold;">
            <span>ยอดสุทธิ:</span> <span>{{ "{:,.2f}".format(total_net) }}</span>
        </div>
        <div class="text-center small mt-3">--- ขอให้โชคดี ---</div>
    </div>
    
    <div class="container no-print" style="max-width: 320px; margin: 0 auto;">
        <button onclick="window.print()" class="btn btn-dark btn-print">🖨️ พิมพ์สลิป (Print)</button>
        <a href="/buy?user={{ username }}&draw={{ draw_date_raw }}&selected={{ selected_target_raw }}" class="btn btn-primary btn-print">⬅️ กลับไปหน้าซื้อเลข (ลูกค้าเดิม)</a>
    </div>
</body>
</html>
"""

REPORTS_CONTENT = """
<div class="card shadow p-4 mb-4">
    <h2 class="text-primary mb-4 fw-bold">📈 รายงานสรุปยอดขายรวมทั้งระบบ</h2>
    <div class="row text-center">
        <div class="col-md-6 mb-2"><div class="p-3 bg-white border border-primary rounded shadow-sm"><h5>ยอดขายรวมทั้งหมด</h5><h2 class="text-primary fw-bold">฿{{ "{:,.2f}".format(rep_total_sales) }}</h2></div></div>
        <div class="col-md-6 mb-2"><div class="p-3 bg-white border border-success rounded shadow-sm"><h5>ยอดสุทธิทั้งหมด</h5><h2 class="text-success fw-bold">฿{{ "{:,.2f}".format(rep_total_net) }}</h2></div></div>
    </div>
</div>

<div class="card shadow p-4">
    <h4 class="text-dark mb-3 fw-bold"><i class="fa-solid fa-users"></i> สรุปยอดขายแยกตามรายบุคคล (แจกแจงตามประเภทหวย)</h4>
    <div class="accordion" id="accordionReports">
        {% for u, data in report_data.items() %}
        <div class="accordion-item mb-2 border rounded">
            <h2 class="accordion-header" id="heading{{ loop.index }}">
                <button class="accordion-button {% if not loop.first %}collapsed{% endif %} fw-bold bg-light" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{{ loop.index }}" aria-expanded="{% if loop.first %}true{% else %}false{% endif %}">
                    <div class="d-flex justify-content-between w-100 pe-3">
                        <span>👤 ผู้ใช้ / เอเย่นต์: <span class="text-primary">{{ u }}</span></span>
                        <span>ยอดขายรวม: <span class="text-danger fw-bold">฿{{ "{:,.2f}".format(data.total_amt) }}</span></span>
                    </div>
                </button>
            </h2>
            <div id="collapse{{ loop.index }}" class="accordion-collapse collapse {% if loop.first %}show{% endif %}" data-bs-parent="#accordionReports">
                <div class="accordion-body">
                    <table class="table table-sm table-bordered text-center align-middle mb-0">
                        <thead class="table-secondary">
                            <tr><th>ประเภทหวย (งวด)</th><th>ยอดขายรวมของหวยนี้</th></tr>
                        </thead>
                        <tbody>
                            {% for lotto_name, amt in data.breakdown.items() %}
                            <tr>
                                <td class="text-start ps-3 fw-bold">{{ lotto_name }}</td>
                                <td class="text-danger fw-bold">฿{{ "{:,.2f}".format(amt) }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                        <tfoot class="table-light">
                            <tr><td class="text-end fw-bold">ยอดสุทธิที่ต้องส่ง:</td><td class="text-success fw-bold fs-6">฿{{ "{:,.2f}".format(data.total_net) }}</td></tr>
                        </tfoot>
                    </table>
                </div>
            </div>
        </div>
        {% else %}
        <div class="text-center text-muted py-3">ยังไม่มีข้อมูลการขายในระบบ</div>
        {% endfor %}
    </div>
</div>
"""

RESULTS_CONTENT = """
<div class="card shadow p-4 mb-4">
    <h2 class="text-success mb-3 fw-bold">🏆 บันทึกผลการออกรางวัลประจำงวด</h2>
    <form method="POST" action="/save-results" class="row g-3">
        <input type="hidden" name="user" value="{{ username }}">
        <input type="hidden" name="draw" value="{{ draw_date }}">
        <div class="col-md-6">
            <label class="form-label fw-bold text-dark">รางวัลที่ 1 (3 ตัวตรง):</label>
            <input type="text" name="prize_1" class="form-control form-control-lg" value="{{ prize_1 }}" required>
        </div>
        <div class="col-md-6">
            <label class="form-label fw-bold text-dark">เลขท้าย 2 ตัว:</label>
            <input type="text" name="bottom_2" class="form-control form-control-lg" value="{{ bottom_2 }}" required>
        </div>
        <div class="col-12">
            <button type="submit" class="btn btn-success btn-lg w-100 fw-bold">💾 บันทึกและคำนวณผลชนะ/แพ้</button>
        </div>
    </form>
</div>

<div class="card shadow p-4">
    <h3 class="text-primary mb-3 fw-bold">📊 รายงานสรุปผลรางวัล (แพ้/ชนะ)</h3>
    <div class="row text-center mb-4">
        <div class="col-md-6 mb-2"><div class="p-3 bg-white border rounded shadow-sm"><h5>จ่ายเงินรางวัลรวม</h5><h3 class="text-danger fw-bold">฿{{ "{:,.2f}".format(total_payout) }}</h3></div></div>
        <div class="col-md-6 mb-2"><div class="p-3 bg-warning text-dark border rounded shadow-sm"><h5>กำไรสุทธิ (หลังหักจ่าย)</h5><h3 class="fw-bold">฿{{ "{:,.2f}".format(total_net - total_payout) }}</h3></div></div>
    </div>
    <div class="table-responsive">
        <table class="table table-striped table-bordered text-center align-middle">
            <thead class="table-dark">
                <tr><th>ลูกค้า</th><th>ผู้บันทึก</th><th>หมายเลข</th><th>ประเภท</th><th>ยอดซื้อ</th><th>เงินรางวัลที่ได้รับ</th></tr>
            </thead>
            <tbody>
                {% for w in winners %}
                <tr>
                    <td><b>{{ w[0] }}</b></td><td><span class="badge bg-secondary">{{ w[1] }}</span></td><td><code class="fs-5">{{ w[2] }}</code></td><td>{{ w[3] }}</td><td>{{ "{:,.2f}".format(w[4] | float) }}</td><td class="text-success fw-bold fs-5">฿{{ "{:,.2f}".format(w[6] | float) }}</td>
                </tr>
                {% else %}
                <tr><td colspan="6" class="text-muted">ยังไม่มีผู้ถูกรางวัลในงวดนี้</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
"""

CUSTOMER_CONTENT = """
<div class="row">
    <div class="col-md-5 mb-4">
        <div class="card shadow p-4">
            {% if edit_customer %}
                <h4 class="text-warning mb-3 fw-bold">✏️ แก้ไขลูกค้า</h4>
                <form method="POST" action="/update-customer">
                    <input type="hidden" name="user" value="{{ username }}">
                    <input type="hidden" name="draw" value="{{ draw_date }}">
                    <input type="hidden" name="customer_id" value="{{ edit_customer[0] }}">
                    <div class="mb-3"><label class="form-label fw-bold">ชื่อลูกค้า:</label><input type="text" name="name" class="form-control" value="{{ edit_customer[1] }}" required></div>
                    <div class="row mb-3">
                        <div class="col"><label class="form-label small">ส่วนลดรวม(%):</label><input type="number" step="0.01" name="disc_total" class="form-control" value="{{ edit_customer[2] or 0 }}"></div>
                        <div class="col"><label class="form-label small">ส่วนลดวิ่ง(%):</label><input type="number" step="0.01" name="disc_run" class="form-control" value="{{ edit_customer[8] or 0 }}"></div>
                    </div>
                    <div class="row mb-3">
                        <div class="col"><label class="form-label small">จ่าย 3ตรง:</label><input type="number" step="0.01" name="pay_3d" class="form-control" value="{{ edit_customer[3] or 500 }}"></div>
                        <div class="col"><label class="form-label small">จ่าย 2ตัว:</label><input type="number" step="0.01" name="pay_2d" class="form-control" value="{{ edit_customer[5] or 70 }}"></div>
                    </div>
                    <div class="row mb-3">
                        <div class="col"><label class="form-label small">จ่ายวิ่งบน:</label><input type="number" step="0.01" name="pay_run_top" class="form-control" value="{{ edit_customer[6] or 3 }}"></div>
                        <div class="col"><label class="form-label small">จ่ายวิ่งล่าง:</label><input type="number" step="0.01" name="pay_run_bot" class="form-control" value="{{ edit_customer[7] or 4 }}"></div>
                    </div>
                    <button type="submit" class="btn btn-warning w-100 fw-bold mb-2">💾 บันทึกแก้ไข</button>
                    <a href="/customers?user={{ username }}&draw={{ draw_date }}" class="btn btn-outline-secondary w-100 fw-bold">ยกเลิก</a>
                </form>
            {% else %}
                <h4 class="text-success mb-3 fw-bold">➕ เพิ่มลูกค้าใหม่</h4>
                <form method="POST" action="/save-customer">
                    <input type="hidden" name="user" value="{{ username }}">
                    <input type="hidden" name="draw" value="{{ draw_date }}">
                    <div class="mb-3"><label class="form-label fw-bold">ชื่อลูกค้า:</label><input type="text" name="name" class="form-control" required></div>
                    <div class="row mb-3">
                        <div class="col"><label class="form-label small">ส่วนลดรวม(%):</label><input type="number" step="0.01" name="disc_total" class="form-control" value="0"></div>
                        <div class="col"><label class="form-label small">ส่วนลดวิ่ง(%):</label><input type="number" step="0.01" name="disc_run" class="form-control" value="0"></div>
                    </div>
                    <div class="row mb-3">
                        <div class="col"><label class="form-label small">จ่าย 3ตรง:</label><input type="number" step="0.01" name="pay_3d" class="form-control" value="500"></div>
                        <div class="col"><label class="form-label small">จ่าย 2ตัว:</label><input type="number" step="0.01" name="pay_2d" class="form-control" value="70"></div>
                    </div>
                    <div class="row mb-3">
                        <div class="col"><label class="form-label small">จ่ายวิ่งบน:</label><input type="number" step="0.01" name="pay_run_top" class="form-control" value="3"></div>
                        <div class="col"><label class="form-label small">จ่ายวิ่งล่าง:</label><input type="number" step="0.01" name="pay_run_bot" class="form-control" value="4"></div>
                    </div>
                    <button type="submit" class="btn btn-success w-100 fw-bold">บันทึกลูกค้า</button>
                </form>
            {% endif %}
        </div>
    </div>
    <div class="col-md-7">
        <div class="card shadow p-4">
            <h4 class="text-primary mb-3 fw-bold">👥 รายชื่อลูกค้า</h4>
            <div class="table-responsive">
                <table class="table table-striped table-bordered text-center align-middle" style="font-size: 0.85rem;">
                    <thead class="table-dark">
                        <tr><th>ID</th><th>ชื่อ</th><th>จ่าย 3ตรง</th><th>จ่าย 2ตัว</th><th>วิ่งบน</th><th>วิ่งล่าง</th><th>จัดการ</th></tr>
                    </thead>
                    <tbody>
                        {% for c in customers_list %}
                        <tr>
                            <td>{{ c[0] }}</td><td><b>{{ c[1] }}</b></td><td>{{ c[3] or 500 }}</td><td>{{ c[5] or 70 }}</td><td class="text-success fw-bold">{{ c[6] or 3 }}</td><td class="text-success fw-bold">{{ c[7] or 4 }}</td>
                            <td><a href="/customers?user={{ username }}&draw={{ draw_date }}&edit_id={{ c[0] }}" class="btn btn-warning btn-sm fw-bold">✏️ แก้ไข</a></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
"""

USERS_CONTENT = """
<div class="row">
    <div class="col-md-5 mb-4">
        <div class="card shadow p-4">
            <h4 class="text-success mb-3 fw-bold">⚙️ สร้างสายงานสมาชิก</h4>
            <form method="POST" action="/save-user-level">
                <input type="hidden" name="user" value="{{ username }}">
                <input type="hidden" name="draw" value="{{ draw_date }}">
                <div class="mb-3"><label class="form-label fw-bold">Username:</label><input type="text" name="new_username" class="form-control" required></div>
                <div class="mb-3"><label class="form-label fw-bold">Password:</label><input type="password" name="new_password" class="form-control" required></div>
                <div class="mb-3">
                    <label class="form-label fw-bold">ระดับสิทธิ์ (Role):</label>
                    <select name="new_role" class="form-select">
                        <option value="Agent">Agent</option><option value="Member">Member</option>
                    </select>
                </div>
                <div class="row mb-3">
                    <div class="col"><label class="form-label small">ส่วนลดรวม(%):</label><input type="number" step="0.01" name="disc_total" class="form-control" value="0"></div>
                    <div class="col"><label class="form-label small">ส่วนลดวิ่ง(%):</label><input type="number" step="0.01" name="disc_run" class="form-control" value="0"></div>
                </div>
                <div class="row mb-3">
                    <div class="col"><label class="form-label small">จ่าย 3ตรง:</label><input type="number" step="0.01" name="pay_3d" class="form-control" value="500"></div>
                    <div class="col"><label class="form-label small">จ่าย 2ตัว:</label><input type="number" step="0.01" name="pay_2d" class="form-control" value="70"></div>
                </div>
                <button type="submit" class="btn btn-success w-100 fw-bold py-2">💾 บันทึกสมาชิก</button>
            </form>
        </div>
    </div>
    <div class="col-md-7">
        <div class="card shadow p-4">
            <h4 class="text-primary mb-3 fw-bold">🗂️ รายชื่อสมาชิกใต้สายงาน</h4>
            <div class="table-responsive">
                <table class="table table-striped table-bordered text-center align-middle" style="font-size: 0.85rem;">
                    <thead class="table-dark">
                        <tr><th>ID</th><th>Username</th><th>สิทธิ์</th><th>จ่าย 3ตรง</th><th>จ่าย 2ตัว</th></tr>
                    </thead>
                    <tbody>
                        {% for u in users_list %}
                        <tr>
                            <td>{{ u[0] }}</td><td><b>{{ u[1] }}</b></td><td><span class="badge bg-secondary">{{ u[2] }}</span></td><td>{{ u[8] or 500 }}</td><td>{{ u[10] or 70 }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
"""

PASSWORD_TEMPLATE = """
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card shadow p-4 border">
            <h3 class="text-primary mb-3 fw-bold">🔑 เปลี่ยนรหัสผ่าน</h3>
            <form method="POST" action="/update-password">
                <input type="hidden" name="user" value="{{ username }}">
                <input type="hidden" name="draw" value="{{ draw_date }}">
                <div class="mb-3"><label class="form-label fw-bold">รหัสผ่านปัจจุบัน:</label><input type="password" name="old_password" class="form-control" required></div>
                <div class="mb-3"><label class="form-label fw-bold">รหัสผ่านใหม่:</label><input type="password" name="new_password" class="form-control" required></div>
                <div class="mb-3"><label class="form-label fw-bold">ยืนยันรหัสผ่านใหม่:</label><input type="password" name="confirm_password" class="form-control" required></div>
                <button type="submit" class="btn btn-primary w-100 fw-bold py-2">💾 บันทึกรหัสผ่าน</button>
            </form>
        </div>
    </div>
</div>
"""

DASHBOARD_CONTENT = """
<div class="card shadow p-4 mb-4">
    <h2 class="text-primary mb-3 fw-bold"><i class="fa-solid fa-chart-pie"></i> แดชบอร์ดสรุปยอดขาย</h2>
    
    <!-- ฟอร์มเลือกช่วงเวลา -->
    <form method="GET" action="/dashboard" class="row g-3 mb-4 bg-light p-3 border rounded shadow-sm">
        <input type="hidden" name="user" value="{{ username }}">
        <input type="hidden" name="draw" value="{{ draw_date }}">
        <div class="col-md-4">
            <label class="form-label fw-bold text-dark">📅 ตั้งแต่วันที่:</label>
            <input type="date" name="start_date" class="form-control" value="{{ start_date }}">
        </div>
        <div class="col-md-4">
            <label class="form-label fw-bold text-dark">📅 ถึงวันที่:</label>
            <input type="date" name="end_date" class="form-control" value="{{ end_date }}">
        </div>
        <div class="col-md-4 d-flex align-items-end">
            <button type="submit" class="btn btn-primary w-100 fw-bold"><i class="fa-solid fa-magnifying-glass"></i> ค้นหาข้อมูล</button>
        </div>
    </form>

    <!-- สรุปยอดรวม -->
    <div class="row text-center mb-4">
        <div class="col-md-6 mb-2">
            <div class="p-3 bg-white border border-primary border-2 rounded shadow-sm">
                <h5 class="text-muted fw-bold">ยอดขายรวมช่วงเวลาที่เลือก</h5>
                <h1 class="text-primary fw-bold">฿{{ "{:,.2f}".format(total_sales) }}</h1>
            </div>
        </div>
        <div class="col-md-6 mb-2">
            <div class="p-3 bg-white border border-success border-2 rounded shadow-sm">
                <h5 class="text-muted fw-bold">ยอดสุทธิรวม</h5>
                <h1 class="text-success fw-bold">฿{{ "{:,.2f}".format(total_net) }}</h1>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <!-- รายละเอียดแบ่งตามผู้ใช้ -->
    <div class="col-md-6 mb-4">
        <div class="card shadow p-3 h-100 border-0">
            <h5 class="text-dark fw-bold mb-3"><i class="fa-solid fa-users"></i> ยอดขายแยกตามผู้ใช้ / เอเย่นต์</h5>
            <ul class="list-group list-group-flush">
                {% for user_sale in user_sales %}
                <li class="list-group-item d-flex justify-content-between align-items-center bg-transparent">
                    <span class="fw-bold text-dark">{{ user_sale[0] }}</span>
                    <span class="badge bg-primary rounded-pill fs-6 px-3 py-2 shadow-sm">฿{{ "{:,.2f}".format(user_sale[1]) }}</span>
                </li>
                {% else %}
                <li class="list-group-item text-muted text-center">ไม่มีข้อมูลในช่วงเวลานี้</li>
                {% endfor %}
            </ul>
        </div>
    </div>
    
    <!-- รายละเอียดแบ่งตามประเภทหวย -->
    <div class="col-md-6 mb-4">
        <div class="card shadow p-3 h-100 border-0">
            <h5 class="text-dark fw-bold mb-3"><i class="fa-solid fa-ticket"></i> ยอดขายแยกตามประเภทหวย</h5>
            <ul class="list-group list-group-flush">
                {% for lotto_sale in lotto_sales %}
                <li class="list-group-item d-flex justify-content-between align-items-center bg-transparent">
                    <span class="fw-bold text-dark">{{ lotto_sale[0] }}</span>
                    <span class="badge bg-danger rounded-pill fs-6 px-3 py-2 shadow-sm">฿{{ "{:,.2f}".format(lotto_sale[1]) }}</span>
                </li>
                {% else %}
                <li class="list-group-item text-muted text-center">ไม่มีข้อมูลในช่วงเวลานี้</li>
                {% endfor %}
            </ul>
        </div>
    </div>
</div>
"""

AUDIT_ALL_CONTENT = """
<div class="card shadow p-4">
    <h2 class="text-primary mb-4 fw-bold">🔍 ตรวจสอบรายการซื้อทั้งหมดในระบบ</h2>
    <div class="table-responsive">
        <table class="table table-striped table-bordered text-center align-middle">
            <thead class="table-dark">
                <tr><th>เวลาทำรายการ</th><th>เลขที่บิล</th><th>ผู้บันทึก</th><th>ลูกค้า</th><th>ประเภท</th><th>หมายเลข</th><th>ยอดซื้อ</th><th>อัตราจ่าย</th></tr>
            </thead>
            <tbody>
                {% for r in audit_rows %}
                <tr>
                    <td><small>{{ r[2] }}</small></td><td><code>{{ r[7] }}</code></td><td><span class="badge bg-secondary">{{ r[3] }}</span></td><td><b>{{ r[5] }}</b></td><td>{{ r[9] }}</td><td><b class="text-primary">{{ r[8] }}</b></td><td>{{ "{:,.2f}".format(r[10] | float) }}</td><td><span class="badge bg-success">{{ r[14] }}</span></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
"""

AUDIT_DISCOUNT_CONTENT = """
<div class="card shadow p-4">
    <h2 class="text-primary mb-3 fw-bold">🔍 ตรวจสอบส่วนลดลูกค้า</h2>
    <div class="table-responsive mt-3">
        <table class="table table-striped table-bordered text-center align-middle">
            <thead class="table-dark">
                <tr><th>เวลา</th><th>เลขที่บิล</th><th>ลูกค้า</th><th>ประเภท</th><th>หมายเลข</th><th>ยอดซื้อ</th><th>ส่วนลด</th><th>ยอดสุทธิ</th></tr>
            </thead>
            <tbody>
                {% for r in discount_rows %}
                <tr>
                    <td><small>{{ r[2] }}</small></td><td><code>{{ r[7] }}</code></td><td><b>{{ r[5] }}</b></td><td>{{ r[9] }}</td><td><b class="text-primary">{{ r[8] }}</b></td><td>{{ "{:,.2f}".format(r[10] | float) }}</td><td class="text-danger fw-bold">{{ "{:,.2f}".format(r[12] | float) }}</td><td class="text-success fw-bold">{{ "{:,.2f}".format(r[13] | float) }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
"""

DB_INSPECTOR_TEMPLATE = """
<div class="card shadow p-4">
    <h2 class="text-primary mb-3 fw-bold">🗄️ Database Inspector</h2>
    <form method="GET" action="/db-inspector" class="mb-4">
        <input type="hidden" name="user" value="{{ username }}">
        <input type="hidden" name="draw" value="{{ draw_date }}">
        <select name="table_name" class="form-select form-select-lg" onchange="this.form.submit()">
            {% for t in tables %}
                <option value="{{ t }}" {% if selected_table == t %}selected{% endif %}>{{ t }}</option>
            {% endfor %}
        </select>
    </form>
    {% if selected_table %}
        <div class="table-responsive">
            <table class="table table-striped table-bordered text-center">
                <thead class="table-dark">
                    <tr>{% for col in columns %}<th>{{ col }}</th>{% endfor %}</tr>
                </thead>
                <tbody>
                    {% for r in rows %}
                    <tr>{% for val in r %}<td>{{ val }}</td>{% endfor %}</tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    {% endif %}
</div>
"""

# ================= Routes เริ่มต้น =================

@app.get("/", response_class=HTMLResponse)
def index():
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
def login_page(error: str = None):
    return Template(LOGIN_TEMPLATE).render(error=error)

@app.post("/login")
def login_action(username: str = Form(...), password: str = Form(...)):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s AND password=%s", (username, password))
        res = c.fetchone()
        conn.close()
        if res: return RedirectResponse(url=f"/campaigns?user={username}", status_code=status.HTTP_303_SEE_OTHER)
        else: return Template(LOGIN_TEMPLATE).render(error="ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง!")
    except Exception as e: return Template(LOGIN_TEMPLATE).render(error=f"Database Error: {str(e)}")

# ================= Routes หน้าหวยหลัก =================

@app.get("/campaigns", response_class=HTMLResponse)
def campaigns_page(user: str, edit_id: int = None, msg: str = None, error: str = None):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        user_res = c.fetchone()
        role = user_res[0] if user_res else "Member"

        c.execute("SELECT lotto_name, draw_date, status, id, close_time, result_timestamp FROM LotteryCampaigns ORDER BY id DESC")
        campaigns = c.fetchall()

        now = get_thai_time()
        active_camps, closed_camps, missing_close = [], [], []

        for camp in campaigns:
            l_name, d_date, stat, c_id, c_time, r_time = camp
            display_status = "เปิดรับแทง"
            is_closed = False

            if not c_time: missing_close.append({"id": c_id, "draw_date": d_date})
            if c_time:
                try:
                    ct = datetime.strptime(c_time, "%Y-%m-%dT%H:%M")
                    if now >= ct: display_status = "รอผลรางวัล"
                except: pass
            if r_time:
                try:
                    rt = datetime.strptime(r_time, "%Y-%m-%d %H:%M:%S")
                    if (now - rt).total_seconds() >= (2 * 24 * 3600):
                        display_status = "ปิดงวด"
                        is_closed = True
                except: pass
            if stat == 'Closed':
                display_status = "ปิดงวด"
                is_closed = True

            camp_dict = {"lotto_name": l_name, "draw_date": d_date, "status": display_status, "id": c_id, "close_time": c_time, "result_time": r_time}
            if is_closed: closed_camps.append(camp_dict)
            else: active_camps.append(camp_dict)

        edit_campaign = None
        if edit_id:
            c.execute("SELECT lotto_name, draw_date, status, id, close_time FROM LotteryCampaigns WHERE id=%s", (edit_id,))
            edit_campaign = c.fetchone()

        conn.close()
        content = Template(CAMPAIGN_TEMPLATE).render(username=user, role=role, active_campaigns=active_camps, closed_campaigns=closed_camps, missing_close_time_campaigns=missing_close, edit_campaign=edit_campaign)
        return Template(LAYOUT).render(username=user, role=role, draw_date="หน้าหลักจัดการงวด", content=content, current_close_time=None, msg=msg, error=error)
    except Exception as e: return f"System Error: {str(e)}"

@app.post("/create-campaign")
def create_campaign(user: str = Form(...), lotto_name: str = Form(...), draw_date: str = Form(...), close_time: str = Form(...)):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("INSERT INTO LotteryCampaigns (lotto_name, draw_date, status, close_time) VALUES (%s, %s, 'Active', %s)", (lotto_name, draw_date, close_time))
        conn.commit(); conn.close()
        return RedirectResponse(url=f"/campaigns?user={user}&msg=สร้างงวดหวยสำเร็จ", status_code=status.HTTP_303_SEE_OTHER)
    except: pass

@app.post("/update-campaign")
def update_campaign(user: str = Form(...), campaign_id: int = Form(...), lotto_name: str = Form(...), draw_date: str = Form(...), close_time: str = Form(...)):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("UPDATE LotteryCampaigns SET lotto_name=%s, draw_date=%s, close_time=%s WHERE id=%s", (lotto_name, draw_date, close_time, campaign_id))
        conn.commit(); conn.close()
        return RedirectResponse(url=f"/campaigns?user={user}&msg=แก้ไขสำเร็จ", status_code=status.HTTP_303_SEE_OTHER)
    except: pass

@app.get("/toggle-campaign")
def toggle_campaign(id: int, user: str):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT status FROM LotteryCampaigns WHERE id=%s", (id,))
        curr = c.fetchone()
        if curr:
            new_status = "Closed" if curr[0] == "Active" else "Active"
            c.execute("UPDATE LotteryCampaigns SET status=%s, result_timestamp=NULL WHERE id=%s", (new_status, id))
            conn.commit()
        conn.close()
    except: pass
    return RedirectResponse(url=f"/campaigns?user={user}", status_code=status.HTTP_303_SEE_OTHER)

# ================= Routes ระบบซื้อ และ เลขอั้น =================

@app.get("/blocked-numbers", response_class=HTMLResponse)
def blocked_numbers_page(user: str, draw: str, msg: str = None, error: str = None, edit_id: int = None):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]
        if role != 'Admin': return RedirectResponse(url=f"/buy?user={user}&draw={draw}", status_code=status.HTTP_303_SEE_OTHER)
        c.execute("SELECT id, draw_date, raw_num, status, type, is_raw FROM BlockedNumbers WHERE (draw_date = %s OR draw_date ILIKE %s) ORDER BY id DESC", (draw, f"%{draw}%"))
        blocked_list = c.fetchall()
        edit_blocked = None
        if edit_id:
            c.execute("SELECT id, draw_date, raw_num, status, type FROM BlockedNumbers WHERE id = %s", (edit_id,))
            edit_blocked = c.fetchone()
        conn.close()
        close_t = get_current_campaign_close_time(draw)
        content = Template(BLOCKED_TEMPLATE).render(username=user, draw_date=draw, blocked_list=blocked_list, edit_blocked=edit_blocked)
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, msg=msg, error=error, current_close_time=close_t)
    except: pass

@app.post("/save-blocked")
def save_blocked(user: str = Form(...), draw: str = Form(...), raw_input: str = Form(...), status: str = Form(...)):
    try:
        conn = connect_db()
        c = conn.cursor()
        cleaned = raw_input.replace('\r\n', ',').replace('\n', ',').replace(' ', ',')
        raw_numbers = [item.strip() for item in cleaned.split(',') if item.strip()]
        insert_data, seen = [], set()
        
        for num_str in raw_numbers:
            t_val = "3ตัว" if len(num_str) == 3 else ("2ตัว" if len(num_str) == 2 else ("วิ่ง" if len(num_str) == 1 else "อื่นๆ"))
            if num_str not in seen:
                insert_data.append((draw.strip(), num_str, status, t_val, True))
                seen.add(num_str)
            for p_num in set("".join(p) for p in itertools.permutations(num_str)):
                if p_num not in seen:
                    insert_data.append((draw.strip(), p_num, status, t_val, False))
                    seen.add(p_num)
                    
        c.executemany("INSERT INTO BlockedNumbers (draw_date, raw_num, status, type, is_raw) VALUES (%s, %s, %s, %s, %s)", insert_data)
        conn.commit()
        conn.close()
        return RedirectResponse(url=f"/blocked-numbers?user={user}&draw={draw}&msg=บันทึกเลขอั้นสำเร็จ", status_code=303)
    except Exception as e:
        print("ข้อผิดพลาดในการบันทึกถูกบล็อก:", e)
        return RedirectResponse(url=f"/blocked-numbers?user={user}&draw={draw}&error=บันทึกไม่สำเร็จ: {str(e)}", status_code=303)
@app.post("/update-blocked")
def update_blocked(user: str = Form(...), draw: str = Form(...), blocked_id: int = Form(...), raw_num: str = Form(...), status: str = Form(...)):
    try:
        conn = connect_db(); c = conn.cursor()
        t_val = "3ตัว" if len(raw_num.strip()) == 3 else ("2ตัว" if len(raw_num.strip()) == 2 else ("วิ่ง" if len(raw_num.strip()) == 1 else "อื่นๆ"))
        c.execute("UPDATE BlockedNumbers SET raw_num=%s, status=%s, type=%s, is_raw=TRUE WHERE id=%s", (raw_num.strip(), status, t_val, blocked_id))
        conn.commit(); conn.close()
        return RedirectResponse(url=f"/blocked-numbers?user={user}&draw={draw}&msg=แก้ไขสำเร็จ", status_code=status.HTTP_303_SEE_OTHER)
    except: pass

@app.get("/delete-blocked")
def delete_blocked(id: int, user: str, draw: str):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("DELETE FROM BlockedNumbers WHERE id = %s", (id,))
        conn.commit(); conn.close()
    except: pass
    return RedirectResponse(url=f"/blocked-numbers?user={user}&draw={draw}", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/clear-blocked")
def clear_blocked(user: str, draw: str):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("DELETE FROM BlockedNumbers WHERE draw_date = %s OR draw_date ILIKE %s", (draw, f"%{draw}%"))
        conn.commit(); conn.close()
    except: pass
    return RedirectResponse(url=f"/blocked-numbers?user={user}&draw={draw}", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/buy", response_class=HTMLResponse)
def buy_page(user: str, draw: str, selected: str = None, msg: str = None):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]
        draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
        c.execute("SELECT lotto_name FROM LotteryCampaigns WHERE draw_date = %s OR draw_date ILIKE %s LIMIT 1", (draw_clean, f"%{draw_clean}%"))
        ln_res = c.fetchone()
        lotto_name_for_bill = ln_res[0] if ln_res else "หวยไม่ระบุ"
        
        c.execute("SELECT id, name, 'Customer' FROM Customers WHERE owner_username=%s", (user,))
        custs = c.fetchall()
        if not custs and role == 'Admin':
            c.execute("SELECT id, name, 'Customer' FROM Customers")
            custs = c.fetchall()
        c.execute("SELECT id, username, 'User' FROM Users WHERE parent_user=%s", (user,))
        agents = c.fetchall()
        all_targets = custs + agents
        if not selected and all_targets: selected = f"{all_targets[0][0]}|{all_targets[0][1]}|{all_targets[0][2]}"
        
        c_id, c_type, customer_name_for_bill = None, None, ""
        preview_bill_no = "TH261026-X-BXX (กำลังประมวลผล)"
        if selected:
            parts = selected.split('|')
            c_id, customer_name_for_bill, c_type = parts[0], parts[1], parts[2]
            preview_bill_no = generate_bill_no(lotto_name_for_bill, draw_clean, c_id)
            
        drafts, sum_amt, sum_disc, sum_net = [], 0.0, 0.0, 0.0
        if c_id:
            c.execute("SELECT id, num, amt_teng, status, type, payout_rate, discount, net FROM TempDraft WHERE username=%s AND customer_id=%s AND customer_type=%s", (user, c_id, c_type))
            for row in c.fetchall():
                drafts.append(row)
                sum_amt += float(row[2] or 0)
                sum_disc += float(row[6] or 0)
                sum_net += float(row[7] or 0)
                
        if role == 'Admin': c.execute("SELECT * FROM Transactions WHERE (draw_date = %s OR draw_date ILIKE %s) ORDER BY id DESC LIMIT 15", (draw_clean, f"%{draw_clean}%"))
        else: c.execute("SELECT * FROM Transactions WHERE ((draw_date = %s OR draw_date ILIKE %s) AND username = %s) ORDER BY id DESC LIMIT 15", (draw_clean, f"%{draw_clean}%", user))
        recent_transactions = c.fetchall()
        conn.close()
        
        b_closed, b_3d, b_2d = get_blocked_display_data(draw_clean)
        close_t = get_current_campaign_close_time(draw_clean)
        curr_time = get_thai_time().strftime("%d/%m/%Y %H:%M")
        content = Template(BUY_CONTENT).render(username=user, draw_date=draw, draw_date_clean=draw_clean, customers=all_targets, selected_target_raw=selected, drafts=drafts, draft_totals={"sum_amt": sum_amt, "sum_disc": sum_disc, "sum_net": sum_net}, block_closed=b_closed, block_3d=b_3d, block_2d=b_2d, recent_transactions=recent_transactions, lotto_name_for_bill=lotto_name_for_bill, customer_name_for_bill=customer_name_for_bill, preview_bill_no=preview_bill_no, preview_time=curr_time)
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, msg=msg, current_close_time=close_t)
    except: pass

@app.post("/add-draft")
def add_draft(user: str = Form(...), draw: str = Form(...), customer_info: str = Form(...), col_num: str = Form(None), col_teng: float = Form(0), col_tod: float = Form(0), raw_input: str = Form(None)):
    parts = customer_info.split('|')
    c_id, c_type = parts[0], parts[2]
    draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
    try:
        conn = connect_db(); c = conn.cursor()
        blocked_dict = get_all_blocked_for_draw(draw_clean)
        table = "Customers" if c_type == 'Customer' else "Users"
        c.execute(f"SELECT pay_3d, pay_3tod, pay_2d, disc_total, disc_3d, disc_2d, disc_run, pay_run_top, pay_run_bot FROM {table} WHERE id=%s", (c_id,))
        res = c.fetchone()
        pay_3d, pay_3tod, pay_2d, disc_total, disc_3d, disc_2d, disc_run, pay_run_top, pay_run_bot = float(res[0] or 500), float(res[1] or 100), float(res[2] or 70), float(res[3] or 0), float(res[4] or 0), float(res[5] or 0), float(res[6] or 0), float(res[7] or 3), float(res[8] or 4)

        insert_data = []
        def process_number(n_str, top_amt, bot_amt):
            b_status = blocked_dict.get(n_str, "ปกติ")
            if len(n_str) == 3:
                if top_amt > 0: insert_data.append((user, c_id, c_type, n_str, top_amt, "3ตัวตรง", pay_3d, top_amt * ((disc_3d if disc_3d > 0 else disc_total) / 100.0), top_amt - (top_amt * ((disc_3d if disc_3d > 0 else disc_total) / 100.0)), b_status))
                if bot_amt > 0: insert_data.append((user, c_id, c_type, n_str, bot_amt, "3ตัวโต๊ด", pay_3tod, bot_amt * ((disc_3d if disc_3d > 0 else disc_total) / 100.0), bot_amt - (bot_amt * ((disc_3d if disc_3d > 0 else disc_total) / 100.0)), b_status))
            elif len(n_str) == 2:
                if top_amt > 0: insert_data.append((user, c_id, c_type, n_str, top_amt, "2ตัวบน", pay_2d, top_amt * ((disc_2d if disc_2d > 0 else disc_total) / 100.0), top_amt - (top_amt * ((disc_2d if disc_2d > 0 else disc_total) / 100.0)), b_status))
                if bot_amt > 0: insert_data.append((user, c_id, c_type, n_str, bot_amt, "2ตัวล่าง", pay_2d, bot_amt * ((disc_2d if disc_2d > 0 else disc_total) / 100.0), bot_amt - (bot_amt * ((disc_2d if disc_2d > 0 else disc_total) / 100.0)), b_status))
            elif len(n_str) == 1:
                if top_amt > 0: insert_data.append((user, c_id, c_type, n_str, top_amt, "วิ่งบน", pay_run_top, top_amt * ((disc_run if disc_run > 0 else disc_total) / 100.0), top_amt - (top_amt * ((disc_run if disc_run > 0 else disc_total) / 100.0)), b_status))
                if bot_amt > 0: insert_data.append((user, c_id, c_type, n_str, bot_amt, "วิ่งล่าง", pay_run_bot, bot_amt * ((disc_run if disc_run > 0 else disc_total) / 100.0), bot_amt - (bot_amt * ((disc_run if disc_run > 0 else disc_total) / 100.0)), b_status))

        if col_num and col_num.strip(): process_number(col_num.strip(), col_teng, col_tod)
        if raw_input and raw_input.strip():
            clean_raw = raw_input.strip().upper().replace(' ', '').replace('X', '*').replace('+', '*').replace('/', '*')
            hold_nums = []
            for block in clean_raw.split(','):
                if not block: continue
                if '=' in block:
                    num_str, amt_str = block.split('=')[0].strip(), block.split('=')[1].strip()
                    if num_str: hold_nums.append(num_str)
                    top, bot = (float(amt_str.split('*')[0] or 0), float(amt_str.split('*')[1] or 0)) if '*' in amt_str else (float(amt_str or 0), 0.0)
                    for n in hold_nums: process_number(n, top, bot)
                    hold_nums = []
                else: hold_nums.append(block.strip())
        if insert_data: c.executemany("INSERT INTO TempDraft (username, customer_id, customer_type, num, amt_teng, type, payout_rate, discount, net, status) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", insert_data)
        conn.commit(); conn.close()
    except: pass
    return RedirectResponse(url=f"/buy?user={user}&draw={draw}&selected={customer_info}", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/delete-draft-item")
def delete_draft_item(id: int, user: str, draw: str, selected: str):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("DELETE FROM TempDraft WHERE id = %s", (id,))
        conn.commit(); conn.close()
    except: pass
    return RedirectResponse(url=f"/buy?user={user}&draw={draw}&selected={selected}", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/edit-draft-item", response_class=HTMLResponse)
def edit_draft_item_page(id: int, user: str, draw: str, selected: str):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT id, num, amt_teng, type FROM TempDraft WHERE id=%s", (id,))
        item = c.fetchone(); conn.close()
        if not item: return RedirectResponse(url=f"/buy?user={user}&draw={draw}&selected={selected}", status_code=status.HTTP_303_SEE_OTHER)
        form_html = f"""<div class="container my-4" style="max-width: 500px;"><div class="card shadow p-4 border border-warning"><h4 class="text-warning mb-3 fw-bold">✏️ แก้ไขรายการร่าง</h4><form method="POST" action="/update-draft-item"><input type="hidden" name="id" value="{id}"><input type="hidden" name="user" value="{user}"><input type="hidden" name="draw" value="{draw}"><input type="hidden" name="selected" value="{selected}"><div class="mb-3"><label class="form-label fw-bold">หมายเลข:</label><input type="text" name="num" class="form-control" value="{item[1]}" required></div><div class="mb-3"><label class="form-label fw-bold">จำนวนเงิน:</label><input type="number" step="any" name="amount" class="form-control" value="{item[2]}" required></div><div class="mb-3"><label class="form-label fw-bold">ประเภท:</label><input type="text" class="form-control" value="{item[3]}" readonly></div><button type="submit" class="btn btn-warning w-100 fw-bold py-2 mb-2">💾 บันทึก</button><a href="/buy?user={user}&draw={draw}&selected={selected}" class="btn btn-outline-secondary w-100 fw-bold">ยกเลิก</a></form></div></div>"""
        return HTMLResponse(form_html)
    except: return RedirectResponse(url=f"/buy?user={user}&draw={draw}&selected={selected}", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/update-draft-item")
def update_draft_item(id: int = Form(...), user: str = Form(...), draw: str = Form(...), selected: str = Form(...), num: str = Form(...), amount: float = Form(...)):
    parts = selected.split('|'); c_id, c_type = parts[0], parts[2]
    try:
        conn = connect_db(); c = conn.cursor()
        table = "Customers" if c_type == 'Customer' else "Users"
        c.execute(f"SELECT disc_total, disc_3d, disc_2d, disc_run FROM {table} WHERE id=%s", (c_id,))
        res = c.fetchone()
        disc_total, disc_3d, disc_2d, disc_run = float(res[0] or 0), float(res[1] or 0), float(res[2] or 0), float(res[3] or 0)
        c.execute("SELECT type FROM TempDraft WHERE id=%s", (id,))
        t_type = c.fetchone()[0]
        d_rate = disc_3d if "3ตัว" in t_type and disc_3d > 0 else (disc_2d if "2ตัว" in t_type and disc_2d > 0 else (disc_run if "วิ่ง" in t_type and disc_run > 0 else disc_total))
        final_disc = amount * (d_rate / 100.0)
        c.execute("UPDATE TempDraft SET num=%s, amt_teng=%s, discount=%s, net=%s, status=%s WHERE id=%s", (num.strip(), amount, final_disc, amount - final_disc, check_number_blocked_status(draw, num.strip()), id))
        conn.commit(); conn.close()
    except: pass
    return RedirectResponse(url=f"/buy?user={user}&draw={draw}&selected={selected}", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/clear-draft")
def clear_draft(user: str, draw: str, selected: str):
    parts = selected.split('|')
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("DELETE FROM TempDraft WHERE username=%s AND customer_id=%s AND customer_type=%s", (user, parts[0], parts[2]))
        conn.commit(); conn.close()
    except: pass
    return RedirectResponse(url=f"/buy?user={user}&draw={draw}&selected={selected}", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/confirm-bill", response_class=HTMLResponse)
def confirm_bill(user: str = Form(...), draw: str = Form(...), customer_info: str = Form(...), lotto_name: str = Form(...)):
    parts = customer_info.split('|'); c_id, c_name, c_type = parts[0], parts[1], parts[2]
    draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
    try:
        bill_no = generate_bill_no(lotto_name, draw_clean, c_id)
        conn = connect_db(); c = conn.cursor()
        table = "Customers" if c_type == 'Customer' else "Users"
        c.execute(f"SELECT disc_total, disc_3d, disc_2d, disc_run, pay_3d, pay_3tod, pay_2d, pay_run_top, pay_run_bot FROM {table} WHERE id=%s", (c_id,))
        c_res = c.fetchone()
        disc_total, disc_3d, disc_2d, disc_run = float(c_res[0] or 0), float(c_res[1] or 0), float(c_res[2] or 0), float(c_res[3] or 0)
        pay_3d_def, pay_3tod_def, pay_2d_def = float(c_res[4] or 500), float(c_res[5] or 100), float(c_res[6] or 70)
        pay_run_top_def, pay_run_bot_def = float(c_res[7] or 3), float(c_res[8] or 4)

        c.execute("SELECT num, type, amt_teng, status FROM TempDraft WHERE username=%s AND customer_id=%s AND customer_type=%s", (user, c_id, c_type))
        drafts = c.fetchall()
        bill_items, total_amt, total_disc, total_net = [], 0.0, 0.0, 0.0
        ts = get_thai_time().strftime("%d/%m/%Y %H:%M:%S")
        
        if drafts:
            insert_transactions = []
            for n, t_type, amt, status_val in drafts:
                amt_val = float(amt or 0)
                final_rate = pay_3d_def if t_type == "3ตัวตรง" else (pay_3tod_def if t_type == "3ตัวโต๊ด" else (pay_2d_def if "2ตัว" in t_type else (pay_run_top_def if t_type == "วิ่งบน" else pay_run_bot_def)))
                d_rate = disc_3d if "3ตัว" in t_type and disc_3d > 0 else (disc_2d if "2ตัว" in t_type and disc_2d > 0 else (disc_run if "วิ่ง" in t_type and disc_run > 0 else disc_total))
                final_disc = amt_val * (d_rate / 100.0)
                final_net = amt_val - final_disc
                insert_transactions.append((draw_clean, ts, user, int(c_id), c_name, c_type, bill_no, n, t_type, amt_val, status_val, final_disc, final_net, final_rate, lotto_name))
                bill_items.append({"num": n, "type": t_type, "amount": amt_val})
                total_amt += amt_val; total_disc += final_disc; total_net += final_net
            c.executemany("INSERT INTO Transactions (draw_date, timestamp, username, customer_id, customer_name, customer_type, bill_no, num, type, amount, status, discount, net, payout_rate, lotto_name) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", insert_transactions)
            c.execute("DELETE FROM TempDraft WHERE username=%s AND customer_id=%s AND customer_type=%s", (user, c_id, c_type))
            conn.commit()
        conn.close()
        content = Template(BILL_PRINT_TEMPLATE).render(lotto_title=lotto_name, draw_date=draw_clean, draw_date_raw=draw, bill_no=bill_no, timestamp=ts, customer_name=c_name, username=user, bill_items=bill_items, total_amt=total_amt, total_disc=total_disc, total_net=total_net, selected_target_raw=customer_info)
        return HTMLResponse(content)
    except: pass

# ================= Routes ระบบรายงาน & แดชบอร์ด & การตั้งค่า (ที่เคยหายไป) =================

@app.get("/results", response_class=HTMLResponse)
def results_page(user: str, draw: str, msg: str = None):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]
        if role != 'Admin': return RedirectResponse(url=f"/buy?user={user}&draw={draw}", status_code=status.HTTP_303_SEE_OTHER)
        draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
        
        c.execute("SELECT prize_1, bottom_2 FROM DrawResults WHERE draw_date = %s OR draw_date ILIKE %s", (draw_clean, f"%{draw_clean}%"))
        res = c.fetchone()
        prize_1 = str(res[0]).strip() if res and res[0] else ""
        bottom_2 = str(res[1]).strip() if res and res[1] else ""

        c.execute("SELECT raw_num, status FROM BlockedNumbers WHERE draw_date = %s OR draw_date ILIKE %s", (draw_clean, f"%{draw_clean}%"))
        half_pay_numbers = set([str(b_num).strip() for b_num, b_status in c.fetchall() if b_status != "ปิดรับ" and b_num])

        c.execute("SELECT SUM(amount), SUM(net) FROM Transactions WHERE (draw_date = %s OR draw_date ILIKE %s)", (draw_clean, f"%{draw_clean}%"))
        sales_res = c.fetchone()
        total_sales = float(sales_res[0] or 0) if sales_res and sales_res[0] else 0.0
        total_net = float(sales_res[1] or 0) if sales_res and sales_res[1] else 0.0

        winners, total_payout = [], 0.0
        c.execute("SELECT customer_name, username, num, type, amount, payout_rate FROM Transactions WHERE (draw_date = %s OR draw_date ILIKE %s)", (draw_clean, f"%{draw_clean}%"))
        for cname, uname, num, ttype, amt, rate in c.fetchall():
            amt_val, rate_val = float(amt or 0), float(rate or 0)
            clean_num, clean_type = str(num).strip(), str(ttype).strip()
            is_winner = False
            if clean_type == "3ตัวตรง" and prize_1 and clean_num == prize_1: is_winner = True
            elif clean_type == "3ตัวโต๊ด" and prize_1 and sorted(clean_num) == sorted(prize_1) and clean_num != prize_1: is_winner = True
            elif clean_type == "2ตัวบน" and prize_1 and len(prize_1) >= 2 and clean_num == prize_1[-2:]: is_winner = True
            elif clean_type == "2ตัวล่าง" and bottom_2 and clean_num == bottom_2: is_winner = True
            elif clean_type == "วิ่งบน" and prize_1 and clean_num in list(prize_1): is_winner = True
            elif clean_type == "วิ่งล่าง" and bottom_2 and clean_num in list(bottom_2): is_winner = True
            
            if is_winner:
                if clean_num in half_pay_numbers: rate_val = rate_val / 2.0
                payout = amt_val * rate_val
                winners.append((cname, uname, clean_num, clean_type, amt_val, rate_val, payout))
                total_payout += payout

        conn.close()
        close_t = get_current_campaign_close_time(draw_clean)
        content = Template(RESULTS_CONTENT).render(username=user, draw_date=draw, prize_1=prize_1, bottom_2=bottom_2, total_sales=total_sales, total_net=total_net, winners=winners, total_payout=total_payout)
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, current_close_time=close_t, msg=msg)
    except: pass

@app.post("/save-results")
def save_results(user: str = Form(...), draw: str = Form(...), prize_1: str = Form(...), bottom_2: str = Form(...)):
    draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("INSERT INTO DrawResults (draw_date, prize_1, bottom_2) VALUES (%s, %s, %s) ON CONFLICT (draw_date) DO UPDATE SET prize_1=EXCLUDED.prize_1, bottom_2=EXCLUDED.bottom_2", (draw_clean, prize_1.strip(), bottom_2.strip()))
        c.execute("UPDATE LotteryCampaigns SET result_timestamp = %s WHERE draw_date = %s OR draw_date ILIKE %s", (get_thai_time().strftime("%Y-%m-%d %H:%M:%S"), draw_clean, f"%{draw_clean}%"))
        conn.commit(); conn.close()
    except: pass
    return RedirectResponse(url=f"/results?user={user}&draw={draw}&msg=บันทึกผลรางวัลสำเร็จ เริ่มนับถอยหลังปิดงวดอัตโนมัติ 2 วัน", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/reports", response_class=HTMLResponse)
def reports_page(user: str, draw: str):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]
        
        if role == 'Admin': c.execute("SELECT username, lotto_name, draw_date, SUM(amount), SUM(net) FROM Transactions GROUP BY username, lotto_name, draw_date")
        else: c.execute("SELECT username, lotto_name, draw_date, SUM(amount), SUM(net) FROM Transactions WHERE username=%s GROUP BY username, lotto_name, draw_date", (user,))
        
        report_data, total_sys_sales, total_sys_net = {}, 0.0, 0.0
        for row in c.fetchall():
            u, l_name, d_date, amt, net = row
            amt, net = float(amt or 0), float(net or 0)
            l_display = f"{l_name if l_name else 'ไม่มีชื่อหวย'} (งวด {d_date})"
            if u not in report_data: report_data[u] = {'total_amt': 0.0, 'total_net': 0.0, 'breakdown': {}}
            report_data[u]['total_amt'] += amt
            report_data[u]['total_net'] += net
            total_sys_sales += amt; total_sys_net += net
            if l_display not in report_data[u]['breakdown']: report_data[u]['breakdown'][l_display] = 0.0
            report_data[u]['breakdown'][l_display] += amt

        conn.close()
        draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
        close_t = get_current_campaign_close_time(draw_clean)
        content = Template(REPORTS_CONTENT).render(rep_total_sales=total_sys_sales, rep_total_net=total_sys_net, report_data=report_data)
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, current_close_time=close_t)
    except: pass

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(user: str, draw: str, start_date: str = None, end_date: str = None):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]

        # ดึงข้อมูลทั้งหมดมาคัดกรองด้วย Python เพื่อป้องกัน Error รูปแบบวันที่ของข้อมูลเก่า
        if role == 'Admin':
            c.execute("SELECT username, COALESCE(lotto_name, 'ไม่ระบุประเภท'), timestamp, amount, net FROM Transactions WHERE timestamp IS NOT NULL")
        else:
            c.execute("SELECT username, COALESCE(lotto_name, 'ไม่ระบุประเภท'), timestamp, amount, net FROM Transactions WHERE timestamp IS NOT NULL AND username = %s", (user,))
        
        rows = c.fetchall()
        conn.close()
        
        total_sales = 0.0
        total_net = 0.0
        user_sales_dict = {}
        lotto_sales_dict = {}

        # แปลงวันที่ที่เลือกจากหน้าเว็บเป็น datetime object
        start_dt = datetime.strptime(start_date, "%Y-%m-%d") if start_date else None
        end_dt = datetime.strptime(end_date, "%Y-%m-%d") if end_date else None
        if end_dt:
            end_dt = end_dt.replace(hour=23, minute=59, second=59) # ครอบคลุมถึงสิ้นวัน

        for r in rows:
            r_user, r_lotto, r_time, r_amt, r_net = r
            
            # ตรวจสอบและแปลงรูปแบบวันที่จากฐานข้อมูล (รองรับทั้งแบบเก่าและแบบใหม่)
            row_dt = None
            try:
                if "/" in r_time:
                    row_dt = datetime.strptime(r_time, "%d/%m/%Y %H:%M:%S")
                elif "-" in r_time:
                    row_dt = datetime.strptime(r_time[:19], "%Y-%m-%d %H:%M:%S")
            except:
                pass # ข้ามกรณีที่วันที่ผิดปกติจริงๆ
            
            # กรองวันที่ให้อยู่ในช่วงที่เลือก
            in_range = True
            if row_dt:
                if start_dt and row_dt < start_dt:
                    in_range = False
                if end_dt and row_dt > end_dt:
                    in_range = False
            else:
                # ถ้าหาวันที่ไม่เจอ แต่มีการกรองวันที่ ให้ถือว่าอยู่นอกเงื่อนไข
                if start_dt or end_dt:
                    in_range = False

            if in_range:
                amt = float(r_amt or 0)
                net = float(r_net or 0)
                
                total_sales += amt
                total_net += net
                
                user_sales_dict[r_user] = user_sales_dict.get(r_user, 0.0) + amt
                lotto_sales_dict[r_lotto] = lotto_sales_dict.get(r_lotto, 0.0) + amt

        # จัดเรียงจากยอดขายมากไปน้อย
        user_sales = sorted(user_sales_dict.items(), key=lambda x: x[1], reverse=True)
        lotto_sales = sorted(lotto_sales_dict.items(), key=lambda x: x[1], reverse=True)

        draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
        close_t = get_current_campaign_close_time(draw_clean)

        content = Template(DASHBOARD_CONTENT).render(
            username=user, draw_date=draw,
            start_date=start_date or "", end_date=end_date or "",
            total_sales=total_sales, total_net=total_net,
            user_sales=user_sales, lotto_sales=lotto_sales
        )
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, current_close_time=close_t)
    except Exception as e:
        return f"Dashboard Error: {str(e)}"

@app.get("/audit-all", response_class=HTMLResponse)
def audit_all_page(user: str, draw: str):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]
        if role != 'Admin': return RedirectResponse(url=f"/buy?user={user}&draw={draw}", status_code=status.HTTP_303_SEE_OTHER)
        draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
        c.execute("SELECT * FROM Transactions WHERE (draw_date = %s OR draw_date ILIKE %s) ORDER BY id DESC", (draw_clean, f"%{draw_clean}%"))
        audit_rows = c.fetchall(); conn.close()
        close_t = get_current_campaign_close_time(draw_clean)
        content = Template(AUDIT_ALL_CONTENT).render(audit_rows=audit_rows)
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, current_close_time=close_t)
    except: pass

@app.get("/audit-discount", response_class=HTMLResponse)
def audit_discount_page(user: str, draw: str):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]
        draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
        if role == 'Admin': c.execute("SELECT * FROM Transactions WHERE (draw_date = %s OR draw_date ILIKE %s) ORDER BY id DESC", (draw_clean, f"%{draw_clean}%"))
        else: c.execute("SELECT * FROM Transactions WHERE ((draw_date = %s OR draw_date ILIKE %s) AND username = %s) ORDER BY id DESC", (draw_clean, f"%{draw_clean}%", user))
        discount_rows = c.fetchall(); conn.close()
        close_t = get_current_campaign_close_time(draw_clean)
        content = Template(AUDIT_DISCOUNT_CONTENT).render(discount_rows=discount_rows)
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, current_close_time=close_t)
    except: pass

@app.get("/db-inspector", response_class=HTMLResponse)
def db_inspector_page(user: str, draw: str, table_name: str = None):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]
        if role != 'Admin': return RedirectResponse(url=f"/buy?user={user}&draw={draw}", status_code=status.HTTP_303_SEE_OTHER)
        c.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;")
        tables = [row[0] for row in c.fetchall()]
        rows, columns = [], []
        selected_table = table_name if table_name in tables else (tables[0] if tables else None)
        if selected_table:
            c.execute(f"SELECT * FROM {selected_table} ORDER BY 1 DESC LIMIT 100;")
            rows = c.fetchall()
            columns = [desc[0] for desc in c.description]
        conn.close()
        draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
        close_t = get_current_campaign_close_time(draw_clean)
        content = Template(DB_INSPECTOR_TEMPLATE).render(tables=tables, selected_table=selected_table, columns=columns, rows=rows, draw_date=draw, username=user)
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, current_close_time=close_t)
    except: pass

@app.get("/customers", response_class=HTMLResponse)
def customers_page(user: str, draw: str, msg: str = None, error: str = None, edit_id: int = None):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]
        c.execute("SELECT id, name, disc_total, pay_3d, pay_3tod, pay_2d, pay_run_top, pay_run_bot, disc_run FROM Customers WHERE owner_username=%s", (user,))
        custs_list = c.fetchall()
        if not custs_list and role == 'Admin':
            c.execute("SELECT id, name, disc_total, pay_3d, pay_3tod, pay_2d, pay_run_top, pay_run_bot, disc_run FROM Customers")
            custs_list = c.fetchall()
        edit_customer = None
        if edit_id:
            c.execute("SELECT id, name, disc_total, pay_3d, pay_3tod, pay_2d, pay_run_top, pay_run_bot, disc_run FROM Customers WHERE id=%s", (edit_id,))
            edit_customer = c.fetchone()
        conn.close()
        draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
        close_t = get_current_campaign_close_time(draw_clean)
        content = Template(CUSTOMER_CONTENT).render(username=user, draw_date=draw, customers_list=custs_list, edit_customer=edit_customer)
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, msg=msg, error=error, current_close_time=close_t)
    except: pass

@app.post("/save-customer")
def save_customer(user: str = Form(...), draw: str = Form(...), name: str = Form(...), disc_total: float = Form(0), disc_run: float = Form(0), pay_3d: float = Form(0), pay_3tod: float = Form(0), pay_2d: float = Form(0), pay_run_top: float = Form(3), pay_run_bot: float = Form(4)):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("INSERT INTO Customers (name, owner_username, discount_type, disc_total, disc_run, pay_3d, pay_3tod, pay_2d, pay_run_top, pay_run_bot) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (name, user, 1, disc_total, disc_run, pay_3d, pay_3tod, pay_2d, pay_run_top, pay_run_bot))
        conn.commit(); conn.close()
        return RedirectResponse(url=f"/customers?user={user}&draw={draw}&msg=เพิ่มลูกค้าสำเร็จ", status_code=status.HTTP_303_SEE_OTHER)
    except: pass

@app.post("/update-customer")
def update_customer(user: str = Form(...), draw: str = Form(...), customer_id: int = Form(...), name: str = Form(...), disc_total: float = Form(0), disc_run: float = Form(0), pay_3d: float = Form(0), pay_3tod: float = Form(0), pay_2d: float = Form(0), pay_run_top: float = Form(3), pay_run_bot: float = Form(4)):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("UPDATE Customers SET name=%s, disc_total=%s, disc_run=%s, pay_3d=%s, pay_3tod=%s, pay_2d=%s, pay_run_top=%s, pay_run_bot=%s WHERE id=%s", (name, disc_total, disc_run, pay_3d, pay_3tod, pay_2d, pay_run_top, pay_run_bot, customer_id))
        conn.commit(); conn.close()
        return RedirectResponse(url=f"/customers?user={user}&draw={draw}&msg=แก้ไขสำเร็จ", status_code=status.HTTP_303_SEE_OTHER)
    except: pass

@app.get("/users", response_class=HTMLResponse)
def users_page(user: str, draw: str, msg: str = None, error: str = None):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]
        c.execute("SELECT id, username, role, parent_user, password, disc_total, disc_3d, disc_2d, pay_3d, pay_3tod, pay_2d, disc_run, pay_run_top, pay_run_bot FROM Users WHERE parent_user=%s", (user,))
        users_list = c.fetchall(); conn.close()
        draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
        close_t = get_current_campaign_close_time(draw_clean)
        content = Template(USERS_CONTENT).render(username=user, role=role, draw_date=draw, users_list=users_list)
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, msg=msg, error=error, current_close_time=close_t)
    except: pass

@app.post("/save-user-level")
def save_user_level(user: str = Form(...), draw: str = Form(...), new_username: str = Form(...), new_password: str = Form(...), new_role: str = Form(...), disc_total: float = Form(0), disc_run: float = Form(0), pay_3d: float = Form(0), pay_3tod: float = Form(0), pay_2d: float = Form(0), pay_run_top: float = Form(3), pay_run_bot: float = Form(4)):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("INSERT INTO Users (username, password, role, parent_user, disc_total, disc_run, pay_3d, pay_3tod, pay_2d, pay_run_top, pay_run_bot) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (new_username, new_password, new_role, user, disc_total, disc_run, pay_3d, pay_3tod, pay_2d, pay_run_top, pay_run_bot))
        conn.commit(); conn.close()
        return RedirectResponse(url=f"/users?user={user}&draw={draw}&msg=สร้างสมาชิกใหม่สำเร็จ", status_code=status.HTTP_303_SEE_OTHER)
    except: pass

@app.get("/system-reset", response_class=HTMLResponse)
def system_reset_page(user: str, error: str = None):
    try:
        conn = connect_db()
        c = conn.cursor()
        # ตรวจสอบสิทธิ์ว่าเป็น Admin จริงหรือไม่
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        res = c.fetchone()
        conn.close()
        
        role = res[0] if res else ""
        if role != 'Admin':
            return RedirectResponse(url=f"/select-market?user={user}", status_code=303)
    except:
        return RedirectResponse(url=f"/select-market?user={user}", status_code=303)

    return Template(SYSTEM_RESET_TEMPLATE).render(username=user, error=error)

@app.post("/execute-system-reset")
def execute_system_reset(username: str = Form(...), admin_password: str = Form(...)):
    try:
        conn = connect_db()
        c = conn.cursor()
        
        # 1. ตรวจสอบรหัสผ่านของ Admin เพื่อความปลอดภัยสูงสุด
        c.execute("SELECT id FROM Users WHERE username=%s AND password=%s AND role='Admin'", (username, admin_password))
        admin_check = c.fetchone()
        
        if not admin_check:
            conn.close()
            return RedirectResponse(url=f"/system-reset?user={username}&error=รหัสผ่าน Admin ไม่ถูกต้อง ไม่สามารถรีเซ็ตระบบได้!", status_code=303)

        # 2. ทำการเคลียร์ข้อมูลในตารางต่างๆ ออกทั้งหมดอย่างหมดจด
        c.execute("DELETE FROM Transactions;")
        c.execute("DELETE FROM TempDraft;")
        c.execute("DELETE FROM BlockedNumbers;")
        c.execute("DELETE FROM CustomerLottoRates;")
        c.execute("DELETE FROM AgentSettlements;")
        c.execute("DELETE FROM DrawResults;")
        c.execute("DELETE FROM Customers;")
        c.execute("DELETE FROM LotteryCampaigns;")
        
        # 3. ลบ Users ทั้งหมด ยกเว้นบัญชี Admin ปัจจุบันของคุณบุญชัย
        c.execute("DELETE FROM Users WHERE username != %s;", (username,))
        
        conn.commit()
        conn.close()
        
        # รีเซ็ตสำเร็จ เด้งกลับไปหน้า Login พร้อมข้อความแจ้งเตือน
        return RedirectResponse(url="/login?error=รีเซ็ตระบบสำเร็จ! ข้อมูลถูกล้างเกลี้ยงพร้อมเริ่มใช้งานจริงแล้ว กรุณาเข้าสู่ระบบใหม่อีกครั้ง", status_code=303)
        
    except Exception as e:
        return RedirectResponse(url=f"/system-reset?user={username}&error=เกิดข้อผิดพลาดในการรีเซ็ต: {str(e)}", status_code=303)

@app.get("/password", response_class=HTMLResponse)
def password_page(user: str, draw: str, msg: str = None, error: str = None):
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT role FROM Users WHERE username=%s", (user,))
        role = c.fetchone()[0]; conn.close()
        draw_clean = draw.split("งวด ")[1].strip() if "งวด " in draw else draw
        close_t = get_current_campaign_close_time(draw_clean)
        content = Template(PASSWORD_TEMPLATE).render(username=user, draw_date=draw)
        return Template(LAYOUT).render(username=user, role=role, draw_date=draw, content=content, msg=msg, error=error, current_close_time=close_t)
    except: pass

@app.post("/update-password")
def update_password(user: str = Form(...), draw: str = Form(...), old_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...)):
    if new_password != confirm_password: return RedirectResponse(url=f"/password?user={user}&draw={draw}&error=รหัสผ่านไม่ตรงกัน!", status_code=status.HTTP_303_SEE_OTHER)
    try:
        conn = connect_db(); c = conn.cursor()
        c.execute("SELECT id FROM Users WHERE username=%s AND password=%s", (user, old_password))
        if not c.fetchone(): return RedirectResponse(url=f"/password?user={user}&draw={draw}&error=รหัสผ่านเดิมไม่ถูกต้อง", status_code=status.HTTP_303_SEE_OTHER)
        c.execute("UPDATE Users SET password=%s WHERE username=%s", (new_password, user))
        conn.commit(); conn.close()
        return RedirectResponse(url=f"/password?user={user}&draw={draw}&msg=เปลี่ยนรหัสผ่านสำเร็จ!", status_code=status.HTTP_303_SEE_OTHER)
    except: pass

# ================= หน้าจอจัดการเรตลูกค้าแยกตามหวย (ระบบหลัก) =================
CUSTOMER_RATES_TEMPLATE = """
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <title>กำหนดเรตอัตราจ่ายและส่วนลดตามหวย</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container my-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>⚙️ กำหนดเรตอัตราจ่าย & ส่วนลด (แยกรายลูกค้า / แยกรายหวย)</h2>
            <a href="/dashboard?user={{ username }}&draw=หน้าหลักจัดการงวด" class="btn btn-secondary">กลับหน้าหลัก</a>
        </div>

        {% if msg %}
        <div class="alert alert-success">{{ msg }}</div>
        {% endif %}

        <div class="card shadow p-4 mb-4">
            <form method="POST" action="/save-customer-lotto-rate">
                <input type="hidden" name="username" value="{{ username }}">
                <div class="row g-3">
                    <div class="col-md-4">
                        <label class="form-label fw-bold">1. เลือกลูกค้า:</label>
                        <select name="customer_id" class="form-select" required>
                            <option value="">-- เลือกลูกค้า --</option>
                            {% for cust in customers %}
                            <option value="{{ cust[0] }}">{{ cust[1] }} (เจ้าของ: {{ cust[2] }})</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label fw-bold">2. เลือกประเภทหวย:</label>
                        <select name="lotto_name" class="form-select" required>
                            <option value="">-- เลือกลอตเตอรี่ / หวย --</option>
                            {% for lotto in lotto_list %}
                            <option value="{{ lotto }}">{{ lotto }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-md-4 d-flex align-items-end">
                        <button type="submit" class="btn btn-primary w-100 fw-bold">💾 บันทึก / อัปเดตเรต</button>
                    </div>
                </div>

                <hr class="my-4">

                <h5 class="fw-bold mb-3 text-primary">💰 กำหนดอัตราจ่าย (Pay Rate)</h5>
                <div class="row g-3 mb-3">
                    <div class="col-md-3"><label class="form-label small">3 ตัวตรง:</label><input type="number" step="any" name="pay_3d" class="form-control" value="500"></div>
                    <div class="col-md-3"><label class="form-label small">3 ตัวโต๊ด:</label><input type="number" step="any" name="pay_3tod" class="form-control" value="100"></div>
                    <div class="col-md-3"><label class="form-label small">2 ตัว (บน/ล่าง):</label><input type="number" step="any" name="pay_2d" class="form-control" value="70"></div>
                    <div class="col-md-3"><label class="form-label small">วิ่งบน:</label><input type="number" step="any" name="pay_run_top" class="form-control" value="3.2"></div>
                    <div class="col-md-3"><label class="form-label small text-danger fw-bold">วิ่งล่าง:</label><input type="number" step="any" name="pay_run_bot" class="form-control" value="4.2"></div>
                </div>

                <h5 class="fw-bold mb-3 text-success">📉 กำหนดส่วนลด (%)</h5>
                <div class="row g-3">
                    <div class="col-md-4"><label class="form-label small">ส่วนลด 3 ตัว (%):</label><input type="number" step="any" name="disc_3d" class="form-control" value="0"></div>
                    <div class="col-md-4"><label class="form-label small">ส่วนลด 2 ตัว (%):</label><input type="number" step="any" name="disc_2d" class="form-control" value="0"></div>
                    <div class="col-md-4"><label class="form-label small">ส่วนลดรวมทุกประเภท (%):</label><input type="number" step="any" name="disc_total" class="form-control" value="0"></div>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
"""

@app.get("/customer-rates-page", response_class=HTMLResponse)
def customer_rates_page(user: str, msg: str = None):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("SELECT id, name, owner_username FROM Customers ORDER BY id DESC")
        customers = c.fetchall()
        c.execute("SELECT DISTINCT lotto_name FROM LotteryCampaigns WHERE lotto_name IS NOT NULL")
        lotto_list = [row[0] for row in c.fetchall()]
        conn.close()
    except Exception as e:
        print("Load Customer Rates Error:", e)
        customers = []
        lotto_list = []
    
    return Template(CUSTOMER_RATES_TEMPLATE).render(
        username=user, customers=customers, lotto_list=lotto_list, msg=msg
    )

@app.post("/save-customer-lotto-rate")
def save_customer_lotto_rate(
    username: str = Form(...), 
    customer_id: int = Form(...), 
    lotto_name: str = Form(...),
    pay_3d: float = Form(500), 
    pay_3tod: float = Form(100), 
    pay_2d: float = Form(70), 
    pay_run_top: float = Form(3.2),
    pay_run_bot: float = Form(4.2),  # เพิ่มช่องรับค่าวิ่งล่าง
    disc_3d: float = Form(0), 
    disc_2d: float = Form(0), 
    disc_total: float = Form(0)
):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO CustomerLottoRates (
                customer_id, lotto_name, pay_3d, pay_3tod, pay_2d, 
                pay_run_top, pay_run_bot, disc_3d, disc_2d, disc_total
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (customer_id, lotto_name) 
            DO UPDATE SET 
                pay_3d = EXCLUDED.pay_3d, 
                pay_3tod = EXCLUDED.pay_3tod, 
                pay_2d = EXCLUDED.pay_2d, 
                pay_run_top = EXCLUDED.pay_run_top, 
                pay_run_bot = EXCLUDED.pay_run_bot, 
                disc_3d = EXCLUDED.disc_3d, 
                disc_2d = EXCLUDED.disc_2d, 
                disc_total = EXCLUDED.disc_total
        """, (customer_id, lotto_name, pay_3d, pay_3tod, pay_2d, pay_run_top, pay_run_bot, disc_3d, disc_2d, disc_total))
        
        conn.commit()
        conn.close()
        msg = "บันทึกเรตอัตราจ่ายและส่วนลดสำเร็จ!"
    except Exception as e:
        msg = f"Error: {str(e)}"
        
    return RedirectResponse(url=f"/customer-rates-page?user={username}&msg={msg}", status_code=303)
@app.get("/logout")
def logout():
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
