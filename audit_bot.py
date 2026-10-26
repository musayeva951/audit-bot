"""
Tekshiruv boti — faqat ruxsat berilgan odamlarga javob beradi.

Nima qiladi:
  * Ruxsatsiz odam yozsa — umuman javob bermaydi, funksiya ishlamaydi.
    /start ham, tugma ham, fayl ham — hammasi jim o'tkaziladi.
  * Ruxsatli odam .py fayl tashlasa — kodni tahlil qilib, zaif va
    ochiq joylarini aniq ko'rsatadi: fayl, qator, xavf darajasi,
    nima uchun xavfli va qanday tuzatish kerak (tayyor tuzatilgan kod bilan).
  * Ruxsatli odam @username yozsa — shu @ ga biriktirilgan, avval
    saqlangan kod bo'lsa, o'shani tekshiradi. @ ning o'zi Telegramdan
    kodni olib bermaydi — bu muhim cheklov, bot uni yashirmaydi:
    @ topilmasa, fayl tashlashni so'raydi.

Bu bot boshqalarning boti kodini o'g'irlamaydi. U faqat egasi o'zi
yuborgan faylni, yoki server botda yaratilgan va kodi serverda
saqlanadigan o'z botlarini tekshiradi.

Muhit (env):
    AUDIT_BOT_TOKEN — shu botning tokeni
    OWNER_ID        — egasi Telegram ID si (har doim ruxsatli)
    ALLOWED_IDS     — vergul bilan qo'shimcha ruxsatli ID lar, ixtiyoriy
    AUDIT_DB_PATH   — ruxsatli odamlar bazasi, standart audit.db
    AUDIT_DATA_DIR  — registry.json joylashgan papka, standart shu papka
"""

import ast
import json
import logging
import os
import re
import sqlite3
from pathlib import Path

TOKEN = os.environ.get("AUDIT_BOT_TOKEN", "")
OWNER_ID = int(os.environ.get("OWNER_ID", "0") or 0)
DATA_DIR = Path(os.environ.get("AUDIT_DATA_DIR", str(Path(__file__).parent)))
DB_PATH = Path(os.environ.get("AUDIT_DB_PATH", str(DATA_DIR / "audit.db")))
REGISTRY_PATH = DATA_DIR / "audit_registry.json"

logging.basicConfig(format="%(asctime)s | %(levelname)s | %(message)s", level=logging.INFO)
log = logging.getLogger("audit_bot")
logging.getLogger("httpx").setLevel(logging.WARNING)

# ---------------------------------------------------------------- ruxsat

def _db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS allowed_users(
                     user_id INTEGER PRIMARY KEY, username TEXT DEFAULT '')""")
    c.commit()
    return c


def init_db():
    with _db() as c:
        if OWNER_ID:
            c.execute("INSERT OR IGNORE INTO allowed_users VALUES (?, '')", (OWNER_ID,))
        for part in os.environ.get("ALLOWED_IDS", "").split(","):
            part = part.strip()
            if part.isdigit():
                c.execute("INSERT OR IGNORE INTO allowed_users VALUES (?, '')", (int(part),))
        c.commit()


def is_allowed(user_id: int) -> bool:
    if not user_id:
        return False
    if OWNER_ID and user_id == OWNER_ID:
        return True
    try:
        with _db() as c:
            return c.execute(
                "SELECT 1 FROM allowed_users WHERE user_id=?", (user_id,)
            ).fetchone() is not None
    except Exception:
        return False


def add_allowed(user_id: int, username: str = "") -> None:
    with _db() as c:
        c.execute("INSERT OR REPLACE INTO allowed_users VALUES (?, ?)", (user_id, username))
        c.commit()


def remove_allowed(user_id: int) -> None:
    with _db() as c:
        c.execute("DELETE FROM allowed_users WHERE user_id=?", (user_id,))
        c.commit()


def list_allowed():
    with _db() as c:
        return c.execute("SELECT user_id, username FROM allowed_users ORDER BY user_id").fetchall()


def load_registry() -> dict:
    try:
        return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_registry(data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REGISTRY_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- tahlil

class Finding:
    def __init__(self, severity, rule, line, snippet, why, fix):
        self.severity = severity  # Yuqori / O'rta / Past
        self.rule = rule
        self.line = line
        self.snippet = snippet
        self.why = why
        self.fix = fix

    def as_dict(self):
        return {"severity": self.severity, "rule": self.rule, "line": self.line,
                "snippet": self.snippet, "why": self.why, "fix": self.fix}


TOKEN_RE = re.compile(r"\b\d{8,}:[\w\-]{30,}\b")
SECRET_NAME_RE = re.compile(r"(?i)(token|api_key|apikey|secret|password|passwd|bot_token)")
DANGEROUS_CALLS = {
    "eval": ("Yuqori", "eval() — kodni to'g'ridan-to'g'ri ishga tushiradi, foydalanuvchi kiritgan matn shu yerga tushsa, botni to'liq egallash mumkin."),
    "exec": ("Yuqori", "exec() — kodni to'g'ridan-to'g'ri ishga tushiradi, foydalanuvchi kiritgan matn shu yerga tushsa, botni to'liq egallash mumkin."),
    "pickle.loads": ("Yuqori", "pickle.loads() — ishonchsiz fayl ochilsa, ichidagi kod ham ishga tushadi."),
    "os.system": ("Yuqori", "os.system() — buyruq qatori orqali ishlaydi, matn tozalanmasa, buyruq qo'shib yuborish mumkin."),
    "subprocess": ("O'rta", "subprocess shell=True bilan ishlasa, buyruq qo'shib yuborish mumkin."),
}


def _snippet(lines, lineno):
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()[:140]
    return ""


def audit_code(source: str, filename: str = "bot.py"):
    """Kod matnini tahlil qilib, Finding ro'yxatini qaytaradi."""
    findings = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [Finding("Yuqori", "Sintaksis xato", e.lineno or 0,
                        _snippet(lines, e.lineno or 0),
                        "Kod ishga tushmaydi, avval sintaksisni tuzatish kerak.",
                        "Xato qatorni ochib, qavs, ikki nuqta yoki qo'shtirnoqni tekshir.")]

    # 1. Qattiq yozilgan token / maxfiy kalit
    for i, line in enumerate(lines, 1):
        if SECRET_NAME_RE.search(line) and "=" in line and re.search(r"['\"][^'\"]{8,}['\"]", line):
            if "os.environ" not in line and "getenv" not in line:
                findings.append(Finding("Yuqori", "Qattiq yozilgan maxfiy kalit", i, _snippet(lines, i),
                    "Token yoki kalit to'g'ridan-to'g'ri kodda yozilgan — kod tarqalsa, kalit ham tarqaladi.",
                    "Kalitni koddan o'chir, env ga qo'y: TOKEN = os.environ.get(\"BOT_TOKEN\", \"\")"))
        m = TOKEN_RE.search(line)
        if m and "os.environ" not in line:
            findings.append(Finding("Yuqori", "Ochiq Telegram token", i, "TOKEN = <yashirildi>",
                "Telegram token ochiq ko'rinib turibdi — uni bilgan odam botni boshqaradi.",
                "BotFather da tokenni yangila (Revoke), yangisini faqat env ga yoz, kodga hech qachon yozma."))

    # 2. Xavfli chaqiruvlar (AST)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}" if isinstance(node.func.value, ast.Name) else node.func.attr
            if name in DANGEROUS_CALLS:
                sev, why = DANGEROUS_CALLS[name]
                findings.append(Finding(sev, f"Xavfli chaqiruv: {name}", node.lineno, _snippet(lines, node.lineno), why,
                    "Bu chaqiruvni o'chir. Matnni tahlil qilish kerak bo'lsa, ast.literal_eval yoki aniq ruxsatli ro'yxat (whitelist) ishlat."))
            if name == "yaml.load" and not any(isinstance(k, ast.keyword) and k.arg == "Loader" for k in node.keywords):
                findings.append(Finding("Yuqori", "yaml.load xavfsiz Loader siz", node.lineno, _snippet(lines, node.lineno),
                    "Loader siz yaml.load ishonchsiz fayldan kod ishga tushirishi mumkin.",
                    "yaml.safe_load(...) ishlat."))
            if name == "subprocess.Popen" or name == "subprocess.run":
                src = ast.get_source_segment(source, node) or ""
                if "shell=True" in src:
                    findings.append(Finding("Yuqori", "subprocess shell=True", node.lineno, _snippet(lines, node.lineno),
                        "shell=True bilan foydalanuvchi matni buyruqqa qo'shilib ketishi mumkin.",
                        "shell=True ni o'chir, buyruqni ro'yxat qilib ber: [\"ls\", \"-l\"] kabi, matnni alohida argument qil."))

    # 3. SQL inyeksiya, ochiq fayl yo'li, CORS, debug
    # Faqat f-string yoki matn + o'zgaruvchi bilan yasalgan so'rov flag qilinadi.
    # views+1 kabi parametrli, xavfsiz so'rovlar flag qilinmaydi.
    for i, line in enumerate(lines, 1):
        low = line.lower()
        if re.search(r"\.execute\s*\(\s*f['\"]", line) or re.search(r"\.execute\s*\(['\"][^'\"]*['\"]\s*\+", line):
            findings.append(Finding("Yuqori", "SQL inyeksiya xavfi — tekshiruv kerak", i, _snippet(lines, i),
                "So'rov ichiga o'zgaruvchi to'g'ridan-to'g'ri qo'shilgan bo'lishi mumkin — agar u foydalanuvchi matni bo'lsa, bazani o'qish, o'chirish mumkin. Ichki ro'yxatdan tanlangan bo'lsa, whitelist ekanini tekshir.",
                "Foydalanuvchi qiymatini parametr qilib ber: c.execute(\"SELECT * FROM users WHERE id=?\", (user_id,)). Jadval/ustun nomi bo'lsa, faqat ruxsatli ro'yxatdan tanla."))
        if "open(" in line and ("../" in line or "user" in low or "input" in low or "text" in low):
            findings.append(Finding("O'rta", "Fayl yo'li ochiq (path traversal)", i, _snippet(lines, i),
                "Foydalanuvchi bergan nom bilan fayl ochilsa, ../ bilan boshqa papkaga chiqish mumkin.",
                "Nomni tekshir: faqat ruxsatli belgilar, Path(name).name qilib ol, asosiy papkadan tashqariga chiqmasligini tekshir."))
        if "allow_origins" in line and "*" in line:
            findings.append(Finding("O'rta", "CORS hamma uchun ochiq", i, _snippet(lines, i),
                "Har qanday sayt API ga murojaat qila oladi.",
                "Faqat o'z saytingni yoz: allow_origins=[\"https://sening-sayting\"]"))
        if re.search(r"debug\s*=\s*True", line):
            findings.append(Finding("Past", "Debug yoqilgan", i, _snippet(lines, i),
                "Jonli botda debug xatoliklar va ichki ma'lumotni ko'rsatishi mumkin.",
                "Jonlida debug=False qil."))

    # 4. Admin tekshiruvi yo'qligi — ehtiyot belgisi (aniq hukm emas)
    text = source
    if ("admin" in text.lower() and "OWNER" not in text and "owner_id" not in text.lower()
            and "is_admin" not in text.lower() and "allowed" not in text.lower()):
        findings.append(Finding("O'rta", "Admin tekshiruvi topilmadi", 0, "admin / qo'shish / o'chirish buyruqlari",
            "Admin buyruqlari bor, lekin egani tekshiradigan kod ko'rinmadi — har kim admin bo'lib qolishi mumkin.",
            "Har bir admin buyruq boshida tekshir: if update.effective_user.id != OWNER_ID: return"))
    # 5. Tokenni chatga / logga chiqarish — faqat o'zgaruvchi sifatida
    # chiqarilsa flag qilinadi, "TOKEN env yo'q" kabi oddiy matn flag qilinmaydi.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("print",):
            for arg in node.args:
                if isinstance(arg, ast.Name) and SECRET_NAME_RE.search(arg.id):
                    findings.append(Finding("O'rta", "Maxfiy kalit log/chat ga chiqishi mumkin", node.lineno, _snippet(lines, node.lineno),
                        "Token o'zgaruvchi sifatida log/chat ga tushsa, uni ko'rgan odam botni egallaydi.",
                        "Tokenni hech qachon print/log/send_message qilma, faqat env dan o'qi."))
                if isinstance(arg, ast.JoinedStr):
                    for v in ast.walk(arg):
                        if isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name) and SECRET_NAME_RE.search(v.value.id):
                            findings.append(Finding("O'rta", "Maxfiy kalit log/chat ga chiqishi mumkin", node.lineno, _snippet(lines, node.lineno),
                                "Token o'zgaruvchi sifatida log/chat ga tushsa, uni ko'rgan odam botni egallaydi.",
                                "Tokenni hech qachon print/log/send_message qilma, faqat env dan o'qi."))
    # 6. API ochiqmi
    if re.search(r"@app\.(get|post|route)\s*\(['\"]/api/", source) and "secret" not in text.lower():
        findings.append(Finding("O'rta", "API tekshiruvi topilmadi", 0, "/api/ yo'nalishlari",
            "API yo'nalishlari bor, lekin maxfiy kalit tekshiruvi ko'rinmadi.",
            "Har bir /api so'rovda secret ni tekshir, noto'g'ri bo'lsa 403 qaytar."))
    return findings


def verdict(findings):
    high = sum(1 for f in findings if f.severity == "Yuqori")
    med = sum(1 for f in findings if f.severity == "O'rta")
    if high:
        return "XAVFLI — tuzatmasdan ishga tushirma"
    if med:
        return "EHTIYOT — o'rta kamchiliklarni tuzat, keyin ishga tushir"
    if findings:
        return "Past kamchiliklar bor, ishga tushirish mumkin"
    return "Yuqori yoki o'rta kamchilik topilmadi"


def format_report(filename, findings):
    high_n = sum(1 for f in findings if f.severity == "Yuqori")
    med_n = sum(1 for f in findings if f.severity == "O'rta")
    out = ["Tekshiruv: " + filename, "Xulosa: " + verdict(findings),
           "Topildi: " + str(len(findings)) + " ta (Yuqori: " + str(high_n) + ", O'rta: " + str(med_n) + ")", ""]
    if not findings:
        out.append("Yuqori yoki o'rta kamchilik topilmadi. Bu kod to'liq xavfsiz degani emas — faqat shu qoidalar bo'yicha tekshirildi.")
        return "\n".join(out)
    for n, f in enumerate(findings, 1):
        loc = f"qator {f.line}" if f.line else "butun kod"
        out.append(f"{n}. [{f.severity}] {f.rule} — {loc}")
        out.append(f"   Kod: {f.snippet}")
        out.append(f"   Nima uchun xavfli: {f.why}")
        out.append(f"   Qanday tuzatish: {f.fix}")
        out.append("")
    out.append("O'rgatish: avval Yuqori kamchiliklarni tuzat, keyin qayta fayl tashla — bot yana tekshirib beradi.")
    return "\n".join(out)


# ---------------------------------------------------------------- Telegram

try:
    from telegram import Update
    from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters
    HAS_TG = True
except Exception:
    HAS_TG = False


def _gate(update):
    """Ruxsatsiz bo'lsa True qaytaradi — chaqiruvchi jim turishi kerak."""
    user = update.effective_user
    if not user or not is_allowed(user.id):
        return True
    # Faqat shaxsiy chatda ishlaydi, guruhda jim turadi
    if update.effective_chat and update.effective_chat.type != "private":
        return True
    return False


if HAS_TG:
    async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if _gate(update):
            return
        await update.message.reply_text(
            "Salom! Men tekshiruv botiman.\n\n"
            "Foydalanish:\n"
            "• .py fayl tashla — kodni tekshirib, zaif joylarini ko'rsataman\n"
            "• @username yoz — avval saqlangan kodi bo'lsa, o'shani tekshiraman\n"
            "• /ruxsatli — ruxsatli odamlar ro'yxati (faqat egasi)\n\n"
            "Eslatma: @ ning o'zi Telegramdan kod olib bermaydi. "
            "Shuning uchun @ topilmasa, fayl tashlashni so'rayman.")

    async def cmd_ruxsatli(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if _gate(update) or update.effective_user.id != OWNER_ID:
            return
        rows = list_allowed()
        text = "Ruxsatli odamlar:\n" + "\n".join(f"• {uid} {name}" for uid, name in rows) if rows else "Hech kim yo'q."
        await update.message.reply_text(text)

    async def cmd_ruxsat(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if _gate(update) or update.effective_user.id != OWNER_ID or not context.args:
            return
        try:
            add_allowed(int(context.args[0]))
            await update.message.reply_text(f"{context.args[0]} ruxsatli ro'yxatga qo'shildi.")
        except Exception:
            return

    async def cmd_ruxsat_ol(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if _gate(update) or update.effective_user.id != OWNER_ID or not context.args:
            return
        try:
            remove_allowed(int(context.args[0]))
            await update.message.reply_text(f"{context.args[0]} ro'yxatdan o'chirildi.")
        except Exception:
            return

    async def _audit_and_reply(message, source, filename):
        findings = audit_code(source, filename)
        report = format_report(filename, findings)
        # Telegram xabar chegarasi uchun bo'lib yuborish
        for i in range(0, len(report), 3800):
            await message.reply_text(report[i:i + 3800])

    async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if _gate(update):
            return
        doc = update.message.document
        if not doc or not doc.file_name.endswith(".py"):
            await update.message.reply_text("Faqat .py fayl tashla.")
            return
        f = await doc.get_file()
        data = await f.download_as_bytearray()
        try:
            source = bytes(data).decode("utf-8")
        except Exception:
            await update.message.reply_text("Faylni o'qib bo'lmadi, utf-8 kodda saqla.")
            return
        await _audit_and_reply(update.message, source, doc.file_name)

    async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if _gate(update):
            return
        text = (update.message.text or "").strip()
        username = text[1:] if text.startswith("@") else None
        if text.startswith("/tekshir") and len(text.split()) > 1:
            username = text.split()[1].lstrip("@")
        if not username:
            await update.message.reply_text("Fayl tashla yoki @username yoz.")
            return
        key = "@" + username.lower()
        registry = load_registry()
        path = registry.get(key) or registry.get(username.lower())
        if not path or not Path(path).exists():
            await update.message.reply_text(
                f"{key} uchun saqlangan kod topilmadi.\n\n"
                "Sababi: @ ning o'zi Telegramdan kod olib bermaydi, "
                "kod faqat egasi yuborgan faylda yoki serverda saqlangan bo'lsa topiladi.\n"
                "Shu botning .py faylini tashla — o'shani tekshirib beraman.")
            return
        source = Path(path).read_text(encoding="utf-8", errors="ignore")
        await _audit_and_reply(update.message, source, f"{username}.py")

    def main():
        init_db()
        if not TOKEN:
            raise SystemExit("AUDIT_BOT_TOKEN env kerak")
        app = ApplicationBuilder().token(TOKEN).build()
        app.add_handler(CommandHandler("start", cmd_start))
        app.add_handler(CommandHandler("ruxsatli", cmd_ruxsatli))
        app.add_handler(CommandHandler("ruxsat", cmd_ruxsat))
        app.add_handler(CommandHandler("ruxsat_ol", cmd_ruxsat_ol))
        app.add_handler(MessageHandler(filters.Document.ALL, on_document))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
        log.info("Tekshiruv bot ishga tushdi")
        app.run_polling()


if __name__ == "__main__":
    main()
