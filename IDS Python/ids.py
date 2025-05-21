#!/usr/bin/env python3
import os
import sqlite3
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import threading
import time
from datetime import datetime
import configparser
import psutil
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, jsonify, render_template
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import sys
from pathlib import Path
import platform
try:
    import logging as scapy_logging
    scapy_logging.getLogger("scapy.runtime").setLevel(scapy_logging.ERROR)
    scapy_logging.getLogger("scapy.loading").setLevel(scapy_logging.ERROR)
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, get_if_addr
    SCAPY_AVAILABLE = True
    # تأكد من أن كل الطبقات الضرورية تم استيرادها
    if not all([IP, TCP, UDP, ICMP]): SCAPY_AVAILABLE = False
except ImportError:
    SCAPY_AVAILABLE = False
    IP, TCP, UDP, ICMP = None, None, None, None # تعريف متغيرات وهمية
    # رسالة تحذير للمستخدم في حالة عدم توفر Scapy
    print("="*60)
    print("تحذير: مكتبة scapy غير مثبتة أو لا يمكن استيرادها.")
    print("سيتم تعطيل ميزات مراقبة الشبكة (NIDS).")
    print("لتثبيتها على كالي/أوبونتو: sudo apt install python3-scapy")
    print("(على ويندوز، تأكد من تثبيت Npcap أولاً ثم pip install scapy)")
    print("="*60)
    
class Colors:
    RESET = '\033[0m'       # رمز إعادة الضبط
    BOLD = '\033[1m'         # رمز الخط العريض
    BLUE = '\033[94m'        # أزرق ساطع
    GOLD = '\033[93m'        # ذهبي (عادة أصفر ساطع في الطرفيات)
    SILVER = '\033[97m'      # فضي (عادة أبيض ساطع أو رمادي فاتح)
    # يمكنك إضافة المزيد من الألوان هنا إذا أردت استخدامها في الرسمة
# --- دالة صغيرة لتغيير رمز العدسة بناءً على حالة التنبيه ---
def dynamic_lens(alert=False):
    """تعيد رمز للعدسة بناءً على ما إذا كان هناك تنبيه نشط."""
    # استخدام '!' للإشارة إلى وجود تنبيه، 'O' للحالة العادية
    return "!" if alert else "O"
# --- فن ASCII لـ IDS Rased ---
# تعريف سطور رسمة "RASED" (تم استخدام Colors)
rased_art_lines_def = [
    f"\n\n",
    f"{Colors.GOLD}██████╗    █████╗  ███████╗ ███████╗ ██████╗{Colors.RESET}",
    f"{Colors.GOLD}██╔══██╗  ██╔══██╗ ██╔════╝ ██╔════╝ ██╔══██╗{Colors.RESET}",
    f"{Colors.GOLD}██████╔╝  ███████║  ████╗   ██████╗  ██║  ██║{Colors.RESET}",
    f"{Colors.GOLD}██╔══██╗  ██╔══██║ ██╔══╝   ██╔═══╝  ██║  ██║{Colors.RESET}",
    f"{Colors.GOLD}██║  ██║  ██║  ██║ ███████╗ ███████╗ ██████╔╝{Colors.RESET}",
    f"{Colors.GOLD}╚═╝  ╚═╝  ╚═╝  ╚═╝ ╚══════╝ ╚══════╝ ╚═════╝{Colors.RESET}"
]
# تعريف سطور رسمة "الراصد" (تم استخدام Colors و dynamic_lens)
# ملاحظة: المسافات في بداية السطر مهمة للمحاذاة البصرية
raded_art_lines_def = [
    f"        {Colors.BOLD}{Colors.GOLD}   ╔════════════◇════════════╗{Colors.RESET}",
    f"       {Colors.BOLD}{Colors.GOLD} ║                           ║{Colors.RESET}",
    f"      {Colors.BOLD}{Colors.GOLD} ║    {Colors.BLUE}     SMART RASED         {Colors.GOLD}║{Colors.RESET}",
    f"     {Colors.BOLD}{Colors.GOLD} ║                               ║{Colors.RESET}",
    f"     {Colors.BOLD}{Colors.GOLD}╔════════════{Colors.BLUE}╔═══════╗{Colors.GOLD}════════════╗{Colors.RESET}",
    f"     {Colors.BOLD}{Colors.GOLD}║            {Colors.BLUE}║   {dynamic_lens()}   ║{Colors.GOLD}            ║{Colors.RESET}", # استدعاء dynamic_lens هنا
    f"     {Colors.BOLD}{Colors.GOLD}╚════════════{Colors.BLUE}╚═══════╝{Colors.GOLD}════════════╝{Colors.RESET}",
    f"         {Colors.BOLD}{Colors.GOLD} ╔═══╗               ╔═══╗{Colors.RESET}",
    f"         {Colors.BOLD}{Colors.GOLD} ║ ▲ ║   {Colors.SILVER}≈≈≈≈≈≈≈≈≈   {Colors.GOLD}║ ▼ ║{Colors.RESET}",
    f"         {Colors.BOLD}{Colors.GOLD} ╚═══╝               ╚═══╝{Colors.RESET}"
]
# --- دالة توليد فن ASCII المدمج لبدء التشغيل ---
def generate_startup_banner(alert=False):
    combined_lines = []
    max_rased_len = 0

    # حساب أقصى طول لسطور RASED (مع محاولة تجاهل رموز ANSI لحساب المسافات بشكل صحيح)
    for line in rased_art_lines_def:
        # طريقة بسيطة لتقدير طول السطر مع تجاهل رموز ANSI الأساسية
        # هذا قد لا يعمل تماماً مع جميع رموز ANSI المعقدة، لكنه يكفي هنا
        clean_line = line.replace(Colors.GOLD, "").replace(Colors.RESET, "")
        # تأكد أنك تتعامل مع رموز ANSI التي تستخدمها في الرسمة هنا إذا كانت هناك رموز أخرى
        if len(clean_line) > max_rased_len:
            max_rased_len = len(clean_line)


    # دمج الأسطر من الرسمتين جنباً إلى جنب
    for i in range(max(len(rased_art_lines_def), len(raded_art_lines_def))):
        rased_line = rased_art_lines_def[i] if i < len(rased_art_lines_def) else ""
        raded_line = raded_art_lines_def[i] if i < len(raded_art_lines_def) else ""
        # حساب المسافة اللازمة للمحاذاة
        clean_rased_line = rased_line.replace(Colors.GOLD, "").replace(Colors.RESET, "")
        padding_needed = max_rased_len - len(clean_rased_line)
        padding = " " * padding_needed
        # دمج السطرين مع المسافة الفاصلة بينهما
        # الألوان مطبقة بالفعل داخل الأسطر الفردية للرسمة
        combined_line = rased_line + padding + "   " + raded_line
        combined_lines.append(combined_line)
    # إعادة الأسطر المدمجة كسلسلة نصية متعددة الأسطر
    return "\n".join(combined_lines).rstrip()
# --- إعدادات Flask والتطبيق ---
app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24)
CORS(app, supports_credentials=True)
auth = HTTPBasicAuth() # إعداد المصادقة الأساسية لويب

config = configparser.ConfigParser()

# BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# CONFIG_PATH = os.path.join(BASE_DIR, "ids_config.ini")



config_path = 'ids_config.ini'

# الأقسام والمفاتيح المطلوبة في ملف الإعدادات
required_sections = {
    'HIDS': ['SENSITIVE_FILES', 'SUSPICIOUS_PROCS', 'WHITELIST_PROCS', 'PROCESS_CHECK_INTERVAL'],
    'NIDS': ['SUSPICIOUS_PORTS', 'MONITOR_ICMP_PING'],
    'NETWORK': ['INTERFACE', 'WHITELIST_IPS'],
    'DATABASE': ['PATH'],
    'LOGGING': ['PATH', 'MAX_SIZE_MB', 'BACKUP_COUNT'],
    'WEB': ['USERNAME', 'PASSWORD', 'HOST', 'PORT']
}

config_ok = True
try:
    config.read(config_path)
except Exception as e:
    print(f"خطأ في قراءة ملف الإعدادات '{config_path}': {e}")
    sys.exit(1)

# التحقق من وجود الأقسام والمفاتيح المطلوبة
for section, keys in required_sections.items():
    if not config.has_section(section):
        print(f"خطأ: القسم '[{section}]' مفقود في ملف '{config_path}'.")
        config_ok = False
        continue
    for key in keys:
        if not config.has_option(section, key):
            print(f"خطأ: المفتاح '{key}' مفقود في القسم '[{section}]' بملف '{config_path}'.")
            config_ok = False

# التحقق من قيمة MONITOR_ICMP_PING إذا كان القسم والمفتاح موجودين
if config_ok and config.has_section('NIDS') and config.has_option('NIDS', 'MONITOR_ICMP_PING'):
    try:
        monitor_icmp_ping_val = config.get('NIDS', 'MONITOR_ICMP_PING').lower()
        if monitor_icmp_ping_val not in ['yes', 'no', 'true', 'false', '1', '0']:
            print(f"خطأ: قيمة المفتاح 'MONITOR_ICMP_PING' في القسم '[NIDS]' يجب أن تكون 'yes' أو 'no'.")
            config_ok = False
    except Exception as e:
         print(f"خطأ في قراءة المفتاح 'MONITOR_ICMP_PING': {e}")
         config_ok = False

# إنهاء السكربت إذا كانت الإعدادات غير صحيحة
if not config_ok:
    sys.exit(1)


# --- فئة لتخزين إعدادات التطبيق التي يتم الوصول إليها عالمياً ---
class AppConfig:
    # قائمة بمسارات الملفات الحساسة التي سيتم مراقبتها بواسطة HIDS (تحويلها إلى مسارات مطلقة ومسارات Path)
    SENSITIVE_FILES = [str(Path(f.strip()).resolve()) for f in config.get('HIDS', 'SENSITIVE_FILES', fallback='').split(',') if f.strip()]


# --- فئة لإدارة التسجيل (Logs) وقاعدة البيانات (Database) ---
class IDSLogger:
    def __init__(self):
        # قراءة مسارات قاعدة البيانات وملف السجل من الإعدادات
        self.db_path_str = config.get('DATABASE', 'PATH')
        self.log_path_str = config.get('LOGGING', 'PATH')

        # تحديد المسار المطلق للسكربت الحالي
        script_dir = Path(os.path.dirname(os.path.abspath(__file__)))

        # تحديد المسارات الكاملة لقاعدة البيانات وملف السجل، وجعلها مطلقة إذا لم تكن كذلك بالفعل
        self.db_path = Path(self.db_path_str)
        if not self.db_path.is_absolute():
            self.db_path = script_dir / self.db_path_str
        self.log_path = Path(self.log_path_str)
        if not self.log_path.is_absolute():
            self.log_path = script_dir / self.log_path_str

        # إنشاء مجلدات قاعدة البيانات والسجل إذا لم تكن موجودة (يتطلب صلاحيات إذا كانت في مسار نظام)
        try:
             self.db_path.parent.mkdir(parents=True, exist_ok=True)
             self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
             print(f"خطأ: فشل إنشاء مجلدات السجل/قاعدة البيانات. تأكد من الصلاحيات. الخطأ: {e}")
             sys.exit(1)


        # تهيئة قاعدة البيانات
        self._init_db()
        # إعداد نظام التسجيل النصي
        self._setup_logging()

    # تهيئة جدول قاعدة البيانات
    def _init_db(self):
        try:
            # الاتصال بقاعدة البيانات (سيتم إنشاؤها إذا لم تكن موجودة)
            # check_same_thread=False للسماح بالوصول من خيوط متعددة (خاصة خادم الويب)
            self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            cursor = self.conn.cursor()

            # إنشاء جدول التنبيهات إذا لم يكن موجوداً
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    source TEXT,
                    message TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    proto TEXT -- عمود لتخزين البروتوكول (TCP, UDP, ICMP)
                )
            ''')
            # التحقق إذا كان عمود 'proto' موجوداً بالفعل، وإضافته إذا لم يكن
            # هذا يسمح بتشغيل السكربت على قاعدة بيانات قديمة لا تحتوي على العمود
            cursor.execute("PRAGMA table_info(alerts)")
            columns = [info[1] for info in cursor.fetchall()]
            if 'proto' not in columns:
                cursor.execute("ALTER TABLE alerts ADD COLUMN proto TEXT")
                self.conn.commit()
                # استخدام print هنا لأنه قد يتم استدعاء init قبل إعداد logging بالكامل
                print("تم إضافة عمود 'proto' إلى جدول التنبيهات.")


            self.conn.commit()
        except sqlite3.Error as e:
            print(f"خطأ فادح في قاعدة البيانات: {e}. المسار: {self.db_path}")
            sys.exit(1)
        except Exception as e:
            print(f"خطأ غير متوقع أثناء تهيئة قاعدة البيانات: {e}")
            sys.exit(1)


    # إعداد نظام التسجيل النصي الدوار
    def _setup_logging(self):
        try:
            # قراءة إعدادات حجم السجل وعدد النسخ الاحتياطية
            max_size_mb = config.getint('LOGGING', 'MAX_SIZE_MB', fallback=10)
            backup_count = config.getint('LOGGING', 'BACKUP_COUNT', fallback=5)

            # إعداد RotatingFileHandler لحجم الملف والدوران
            handler = RotatingFileHandler(str(self.log_path), maxBytes=max_size_mb * 1024 * 1024, backupCount=backup_count, encoding='utf-8')
            # إعداد BasicConfig للمستوى والتنسيق والمتحكمات (Handlers)
            logging.basicConfig(
                level=logging.INFO, # مستوى التسجيل الافتراضي (INFO وما فوق)
                format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s',
                handlers=[handler, logging.StreamHandler(sys.stdout)] # التسجيل في ملف وإلى الخرج القياسي
            )
            # الحصول على logger باسم محدد لاستخدامه في السكربت
            self.logger = logging.getLogger('IDS')

        except Exception as e:
            print(f"خطأ فادح عند إعداد التسجيل: {e}. المسار: {self.log_path}")
            sys.exit(1)

    # دالة لتسجيل التنبيهات في قاعدة البيانات وملف السجل
    def log_alert(self, alert_type, message, source="System", proto=None):
        """يسجل تنبيهاً في قاعدة البيانات وملف السجل."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # بناء رسالة السجل النصي
        log_message = f"[{alert_type}] {message} (Source: {source})"
        if proto:
             log_message += f" (Proto: {proto})" # إضافة البروتوكول إذا كان موجوداً

        # تسجيل الرسالة في ملف السجل بناءً على نوع التنبيه
        if "ALERT" in alert_type.upper() or "WARNING" in alert_type.upper():
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)

        # حفظ التنبيه في قاعدة البيانات
        try:
            # استخدام 'with self.conn:' يضمن commit() أو rollback() تلقائياً
            with self.conn:
                 self.conn.execute(
                     "INSERT INTO alerts (type, source, message, timestamp, proto) VALUES (?, ?, ?, ?, ?)",
                     (alert_type, source, message, timestamp, proto)
                 )
        except sqlite3.Error as e:
             self.logger.error(f"خطأ في قاعدة البيانات عند تسجيل التنبيه: {e}")
        except Exception as e:
             self.logger.error(f"خطأ غير متوقع عند تسجيل التنبيه في قاعدة البيانات: {e}")


# --- فئة لمراقبة تغييرات الملفات (HIDS) ---
class FileMonitor:
    def __init__(self, logger_instance):
        self.logger = logger_instance # استخدام كائن Logger
        self.file_hashes = {} # قاموس لتخزين تجزئات الملفات (المسار -> التجزئة)
        self.watched_files = set() # مجموعة مسارات Path للملفات التي يجب مراقبتها تحديداً
        self.observer = None # كائن مراقب watchdog

        # تهيئة تجزئات الملفات وقائمة المراقبة
        self._init_hashes_and_files()

    # حساب تجزئة (Hash) لملف معين
    def _calculate_hash(self, file_path_obj: Path):
        """يحسب تجزئة SHA256 لملف. يعيد None في حالة الخطأ."""
        try:
            # التحقق من أن الملف موجود وهو ملف فعلي
            if not file_path_obj.exists() or not file_path_obj.is_file():
                 return None # لا يمكن حساب تجزئة لشيء غير موجود أو ليس ملفاً

            hasher = hashlib.sha256()
            # فتح الملف للقراءة الثنائية
            with file_path_obj.open('rb') as f:
                # قراءة الملف على دفعات لتجنب استهلاك الذاكرة للملفات الكبيرة
                while True:
                    chunk = f.read(4096) # قراءة 4 كيلوبايت في كل مرة
                    if not chunk: break # التوقف عند نهاية الملف
                    hasher.update(chunk) # تحديث الهاشر بالدفعة المقروءة
            return hasher.hexdigest() # إعادة التجزئة النهائية كنص سداسي عشري
        except PermissionError:
             self.logger.logger.error(f"FileMonitor: لا تملك الصلاحيات الكافية لقراءة الملف {file_path_obj}")
             return None
        except FileNotFoundError:
             # قد يحدث هذا إذا تم حذف الملف بين التحقق من وجوده ومحاولة فتحه
             self.logger.logger.error(f"FileMonitor: لم يتم العثور على الملف {file_path_obj} أثناء حساب التجزئة.")
             return None
        except Exception as e:
            self.logger.logger.error(f"FileMonitor: خطأ غير متوقع بحساب تجزئة {file_path_obj}: {e}")
            return None

    # تهيئة التجزئات الأولية وقائمة الملفات للمراقبة
    def _init_hashes_and_files(self):
        """يحسب التجزئات الأولية للملفات الحساسة ويحدد المجلدات التي ستتم مراقبتها."""
        self.logger.logger.info("FileMonitor: تهيئة مراقبة الملفات...")
        count = 0 # عداد للملفات التي تمكننا من مراقبتها بنجاح
        for file_str in AppConfig.SENSITIVE_FILES:
            file_path = Path(file_str) # تحويل المسار النصي إلى كائن Path

            # التحقق من وجود الملف وأنه ملف فعلاً
            if file_path.exists() and file_path.is_file():
                current_hash = self._calculate_hash(file_path)
                if current_hash:
                    self.file_hashes[str(file_path)] = current_hash # تخزين التجزئة باستخدام المسار كنص
                    self.watched_files.add(file_path) # إضافة كائن Path إلى مجموعة المراقبة
                    count += 1
                else:
                    # إذا لم نتمكن من حساب التجزئة (غالباً بسبب الصلاحيات)، نسجل تحذيراً
                    self.logger.logger.warning(f"FileMonitor: تخطي مراقبة '{file_str}' بسبب مشكلة (ربما صلاحيات).")
            else:
                # إذا كان المسار المحدد غير موجود أو ليس ملفاً
                self.logger.logger.warning(f"FileMonitor: ملف حساس '{file_str}' غير موجود أو ليس ملفاً.")

        self.logger.logger.info(f"FileMonitor: اكتملت تهيئة الملفات. المراقبة: {count} ملفات من أصل {len(AppConfig.SENSITIVE_FILES)}.")

    # بدء مراقب الملفات (Watcher)
    def start(self):
        """يبدأ مراقب الملفات باستخدام watchdog. يعيد كائن Observer أو None."""
        if not self.watched_files:
            self.logger.logger.warning("FileMonitor: قائمة الملفات للمراقبة فارغة. لن يتم بدء مراقب الملفات.")
            return None # لا يوجد شيء لمراقبته

        # معالج الأحداث المخصص
        event_handler = FileSystemEventHandler()
        # ربط الدوال المخصصة بالأحداث
        event_handler.on_modified = self._on_modified
        event_handler.on_created = self._on_created
        event_handler.on_deleted = self._on_deleted

        # إنشاء كائن المراقب. نستخدم PollingObserver إذا كان النظام لا يدعم inotify
        self.observer = Observer()

        # تحديد المجلدات الأبوية للملفات المراقبة لتسجيلها للمراقبة بواسطة watchdog
        watched_dirs = set()
        for file_path_obj in self.watched_files:
            parent_dir = file_path_obj.parent # الحصول على المجلد الأب
            # التحقق من أن المجلد الأب لم تتم إضافته بالفعل للمراقبة وأنه موجود ومجلد فعلاً
            if parent_dir not in watched_dirs and parent_dir.exists() and parent_dir.is_dir():
                # تسجيل المجلد الأب للمراقبة. recursive=False لأننا نهتم بالأحداث في هذا المجلد فقط
                # التي تؤثر على الملفات الموجودة فيه والمراقبة لدينا.
                try:
                    self.observer.schedule(event_handler, path=str(parent_dir), recursive=False)
                    watched_dirs.add(parent_dir)
                    self.logger.logger.debug(f"FileMonitor: تمت جدولة مراقبة المجلد: {parent_dir}")
                except Exception as e:
                     self.logger.logger.error(f"FileMonitor: فشل جدولة مراقبة المجلد {parent_dir}: {e}")


        if not watched_dirs:
             self.logger.logger.warning("FileMonitor: لم يتم العثور على أي مجلدات صالحة للملفات المراقبة. لن يتم بدء مراقب الملفات.")
             return None # لا يوجد مجلدات صالحة للمراقبة

        try:
            # بدء خيط المراقب
            self.observer.start()
            self.logger.logger.info(f"FileMonitor: بدء مراقب الملفات على {len(watched_dirs)} مجلد(ات).")
            return self.observer # إعادة الكائن المراقب للتحكم فيه لاحقاً
        except Exception as e:
            self.logger.logger.error(f"FileMonitor: فشل بدء مراقب الملفات: {e}")
            return None

    # معالج عام لأحداث الملفات
    def _handle_event(self, event_type, event_src_path_str):
        """يعالج أحداث الملفات ويتحقق مما إذا كانت تتعلق بملف حساس."""
        event_file_path = Path(event_src_path_str).resolve() # الحصول على المسار المطلق للملف المتأثر
        self.logger.logger.debug(f"FileMonitor: حدث '{event_type}' لـ {event_file_path}") # تسجيل الحدث للمراجعة

        # التحقق مما إذا كان الملف المتأثر هو أحد الملفات الحساسة التي نراقبها
        if event_file_path in self.watched_files:
            # إذا كان الحدث تعديل
            if event_type == 'modified':
                 self._check_file_modification(event_file_path)
            # إذا كان الحدث حذف
            elif event_type == 'deleted':
                 self.logger.log_alert("HIDS_ALERT", f"حذف ملف حساس: {event_file_path}", "FileMonitor")
                 # إزالة الملف من قائمة التجزئات و قائمة المراقبة المحلية (لا يمكن مراقبته بعد حذفه)
                 if str(event_file_path) in self.file_hashes:
                      del self.file_hashes[str(event_file_path)]
                 self.watched_files.discard(event_file_path)
                 self.logger.logger.info(f"FileMonitor: تمت إزالة {event_file_path} من المراقبة.")
            # إذا كان الحدث إنشاء (في مجلد مراقب)
            elif event_type == 'created':
                # ملاحظة: watchdog يبلغ عن إنشاء ملف في مجلد مراقب حتى لو لم يكن في قائمة SENSITIVE_FILES الأصلية.
                # يمكن استخدام هذا لاكتشاف إنشاء ملفات في مسارات حساسة.
                self.logger.log_alert("HIDS_ALERT", f"إنشاء ملف في مسار حساس: {event_file_path}", "FileMonitor")
                # حاول حساب التجزئة للملف الجديد وإضافته للقائمة المحلية لمراقبته إذا تم تعديله لاحقاً
                new_hash = self._calculate_hash(event_file_path)
                if new_hash:
                     self.file_hashes[str(event_file_path)] = new_hash
                     # يمكن إضافة الملف الجديد إلى self.watched_files هنا إذا أردنا مراقبة التغييرات عليه أيضاً
                     # self.watched_files.add(event_file_path) # اختياري: قم بإلغاء التعليق إذا أردت مراقبة التغييرات على الملف الجديد أيضاً
                     self.logger.logger.debug(f"FileMonitor: تمت إضافة تجزئة للملف المنشأ حديثاً {event_file_path}.")
                else:
                     self.logger.logger.warning(f"FileMonitor: فشل حساب تجزئة للملف المنشأ حديثاً {event_file_path}.")


    # معالجات أحداث watchdog (مربوطة بوظيفة handle_event)
    def _on_modified(self, event):
        if not event.is_directory: # تجاهل أحداث التعديل على المجلدات
            self._handle_event('modified', event.src_path)

    def _on_created(self, event):
         if not event.is_directory: # تجاهل أحداث الإنشاء للمجلدات
             self._handle_event('created', event.src_path)

    def _on_deleted(self, event):
         if not event.is_directory: # تجاهل أحداث الحذف للمجلدات
             self._handle_event('deleted', event.src_path)

    # التحقق من تعديل الملف بناءً على التجزئة
    def _check_file_modification(self, file_path_obj: Path):
        """يحسب تجزئة الملف الحالي ويقارنها بالتجزئة المخزنة."""
        current_hash = self._calculate_hash(file_path_obj)
        if current_hash is None:
            self.logger.logger.error(f"FileMonitor: لم يتمكن من حساب تجزئة للملف المعدل {file_path_obj}.")
            return # لا يمكن المتابعة بدون التجزئة

        original_hash = self.file_hashes.get(str(file_path_obj))

        # إذا كانت هناك تجزئة مخزنة ومختلفة عن التجزئة الحالية
        if original_hash and original_hash != current_hash:
            self.logger.log_alert("HIDS_ALERT", f"تعديل ملف حساس: {file_path_obj}", "FileMonitor")
            self.file_hashes[str(file_path_obj)] = current_hash # تحديث التجزئة المخزنة بالتجزئة الجديدة
            self.logger.logger.info(f"FileMonitor: تحديث تجزئة {file_path_obj} بعد التعديل.")
        elif original_hash is None:
            # هذه الحالة قد تحدث إذا كان الملف موجوداً ولكن لم يتمكن من حساب تجزئته عند البدء، ثم تم تعديله وأصبح ممكناً.
            # أو إذا تم إنشاء الملف أثناء تشغيل المراقب وتم تعديله لاحقاً.
            self.logger.log_alert("HIDS_ALERT", f"تعديل ملف حساس ({file_path_obj}) لم تكن تجزئته الأولية متاحة.", "FileMonitor")
            self.file_hashes[str(file_path_obj)] = current_hash # تخزين التجزئة الجديدة للمقارنات المستقبلية
            self.logger.logger.info(f"FileMonitor: تخزين تجزئة للملف المعدل {file_path_obj} التي لم تكن متوفرة مسبقاً.")


    # إيقاف مراقب الملفات
    def stop(self):
        """يوقف خيط مراقب الملفات التابع لـ watchdog."""
        if self.observer and self.observer.is_alive():
             self.logger.logger.info("FileMonitor: طلب إيقاف مراقب الملفات...")
             self.observer.stop() # إرسال طلب إيقاف
             self.observer.join(timeout=5.0) # الانتظار حتى يكمل الخيط عمله (بمهلة)
             if not self.observer.is_alive():
                 self.logger.logger.info("FileMonitor: تم إيقاف مراقب الملفات بنجاح.")
             else:
                 self.logger.logger.warning("FileMonitor: مراقب الملفات لم يتوقف ضمن المهلة المحددة.")
        self.observer = None # إعادة تعيين الكائن بعد الإيقاف


# --- فئة لمراقبة العمليات (HIDS) ---
class ProcessMonitor:
    def __init__(self, logger_instance, config_obj):
        self.logger = logger_instance # كائن Logger
        self.config = config_obj # كائن Configuration
        self.running = threading.Event() # Event للتحكم في حلقة المراقبة (بدء/إيقاف)
        self.monitor_thread = None # خيط التشغيل الخاص بالمراقبة
        self.alerted_pids = set() # مجموعة لتتبع PIDs العمليات التي تم التنبيه عليها بالفعل لتجنب التكرار المستمر

        # قراءة قوائم العمليات المشبوهة والموثوقة من الإعدادات (تحويلها إلى مجموعة حروف صغيرة)
        suspicious_str = self.config.get('HIDS', 'SUSPICIOUS_PROCS', fallback='')
        whitelist_str = self.config.get('HIDS', 'WHITELIST_PROCS', fallback='')
        self.suspicious_procs = {p.strip().lower() for p in suspicious_str.split(',') if p.strip()}
        self.whitelist_procs = {p.strip().lower() for p in whitelist_str.split(',') if p.strip()}

        # قراءة الفاصل الزمني للفحص
        try:
             self.check_interval = self.config.getint('HIDS', 'PROCESS_CHECK_INTERVAL', fallback=20)
             if self.check_interval <= 0: self.check_interval = 20 # قيمة افتراضية صالحة
        except ValueError:
             self.logger.logger.error("ProcessMonitor: قيمة 'PROCESS_CHECK_INTERVAL' في [HIDS] يجب أن تكون عدد صحيح موجب. استخدام القيمة الافتراضية 20.")
             self.check_interval = 20

        self.logger.logger.info(f"ProcessMonitor: تهيئة. مشبوه: {len(self.suspicious_procs)}, موثوق: {len(self.whitelist_procs)}. الفاصل الزمني: {self.check_interval} ثواني.")

    # دالة فحص العمليات
    def _check_processes(self):
        """تفحص العمليات الجارية بحثاً عن أسماء مشبوهة ليست في القائمة الموثوقة."""
        current_pids = set() # مجموعة لتخزين الـ PIDs الحالية للعمليات المفحوصة
        try:
            # المرور على جميع العمليات الجارية باستخدام psutil
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'].lower() # اسم العملية بحروف صغيرة
                    current_pids.add(pid) # إضافة الـ PID الحالي لقائمة العمليات الجارية

                    # التحقق: إذا كان الاسم مشبوه + ليس موثوق + لم يتم التنبيه عليه مسبقاً بهذا الـ PID
                    if name in self.suspicious_procs and name not in self.whitelist_procs and pid not in self.alerted_pids:
                        # سجل التنبيه
                        self.logger.log_alert(
                            'HIDS_ALERT',
                            f"عملية مشبوهة: {proc.info['name']} (PID:{pid}, User:{proc.info.get('username','N/A')})",
                            'ProcessMonitor'
                        )
                        self.alerted_pids.add(pid) # إضافة الـ PID إلى قائمة التنبيهات المسجلة

                # معالجة الأخطاء المحتملة أثناء الوصول لمعلومات العملية
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue # تجاهل العمليات التي لم يعد لها وجود أو لا يمكن الوصول إليها
                except Exception as e:
                     self.logger.logger.error(f"ProcessMonitor: خطأ بمعالجة PID {getattr(proc,'pid','UKN')}: {e}")

            # إزالة الـ PIDs التي لم تعد موجودة من قائمة التنبيهات المسجلة
            # (حتى لا تنمو القائمة بلا نهاية)
            pids_to_remove = self.alerted_pids - current_pids
            if pids_to_remove:
                 self.alerted_pids.difference_update(pids_to_remove)
                 # self.logger.logger.debug(f"ProcessMonitor: تمت إزالة PIDs من قائمة التنبيهات المسجلة: {list(pids_to_remove)}") # اختياري للتصحيح

        except Exception as e:
            # تسجيل أي خطأ يحدث أثناء عملية الفحص الكاملة للعمليات
            self.logger.logger.error(f"ProcessMonitor: خطأ بفحص العمليات: {e}", exc_info=True)

    # حلقة مراقبة العمليات التي تعمل في خيط منفصل
    def _monitor_loop(self):
        """الحلقة الرئيسية لفحص العمليات بشكل دوري."""
        self.logger.logger.info("ProcessMonitor: بدء حلقة مراقبة العمليات...")
        # تستمر الحلقة طالما أن 'running' Event مضبوطة
        while self.running.is_set():
            self._check_processes() # نفذ فحص العمليات
            # انتظر الفاصل الزمني المحدد أو استيقظ فوراً إذا تم مسح 'running' Event
            self.running.wait(self.check_interval)
        self.logger.logger.info("ProcessMonitor: إيقاف حلقة مراقبة العمليات.")

    # بدء خيط مراقبة العمليات
    def start(self):
        """يبدأ خيط مراقبة العمليات إذا لم يكن يعمل بالفعل."""
        if not self.suspicious_procs:
            self.logger.logger.warning("ProcessMonitor: قائمة العمليات المشبوهة فارغة. لن يتم بدء مراقب العمليات.")
            return # لا يوجد عمليات مشبوهة لمراقبتها

        # التحقق مما إذا كان الخيط غير موجود أو لا يعمل
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.running.set() # ضبط Event لبدء الحلقة
            # إنشاء الخيط وتحديد الدالة الهدف واسم الخيط وجعله Daemon (يتوقف عند إغلاق البرنامج الرئيسي)
            self.monitor_thread = threading.Thread(target=self._monitor_loop, name="ProcessMonitorThread", daemon=True)
            self.monitor_thread.start() # بدء الخيط
            self.logger.logger.info("ProcessMonitor: تم بدء خيط مراقبة العمليات.")

    # إيقاف خيط مراقبة العمليات
    def stop(self):
        """يطلب إيقاف خيط مراقبة العمليات وينتظر إكماله."""
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.logger.logger.info("ProcessMonitor: طلب إيقاف خيط مراقبة العمليات...")
            self.running.clear() # مسح Event لإنهاء حلقة المراقبة
            # الانتظار حتى ينتهي الخيط (بمهلة للسماح له بإنهاء دورته الحالية)
            self.monitor_thread.join(timeout=self.check_interval + 5)
            if not self.monitor_thread.is_alive():
                self.logger.logger.info("ProcessMonitor: تم إيقاف خيط مراقبة العمليات بنجاح.")
            else:
                self.logger.logger.warning("ProcessMonitor: خيط مراقبة العمليات لم يتوقف ضمن المهلة المحددة.")
        self.monitor_thread = None # إعادة تعيين الكائن بعد الإيقاف


# --- فئة مراقبة الشبكة (NIDS) ---
class NetworkMonitor:
    def __init__(self, logger_instance, config_obj):
        self.logger = logger_instance # كائن Logger
        self.config = config_obj # كائن Configuration
        self.running = threading.Event() # Event للتحكم في حلقة التقاط الحزم
        self.monitor_thread = None # خيط التشغيل الخاص بالمراقبة
        self.interface_name = None # اسم واجهة الشبكة للمراقبة
        self.suspicious_ports = set() # مجموعة المنافذ المشبوهة
        self.whitelist_ips = set() # مجموعة عناوين IP الموثوقة
        self._monitor_icmp_ping = False # هل تتم مراقبة ICMP Ping؟

        # قاموس لتخزين التنبيهات الحديثة (مفتاح التنبيه -> timestamp) لتجنب التكرار السريع
        self.recent_alerts_cache = {}
        # قفل لحماية الوصول المتزامن إلى ذاكرة التنبيهات المؤقتة من خيط Sniffing
        self.recent_alerts_lock = threading.Lock()
        # المدة التي يتم فيها اعتبار التنبيه مكرراً (بالثواني) لنفس الاتجاه/النوع
        self.alert_cache_expiry = 10

        # إذا لم تكن Scapy متاحة، لا يمكن تهيئة مراقبة الشبكة
        if not SCAPY_AVAILABLE:
            self.logger.logger.error("NetworkMonitor: Scapy غير متاحة، لا يمكن تهيئة مراقبة الشبكة.")
            return

        # قراءة إعدادات الشبكة
        self._configure()

        # تحقق نهائي مما إذا كانت المراقبة ممكنة بناءً على التهيئة
        if not self.interface_name or (not self.suspicious_ports and not self._monitor_icmp_ping):
             self.logger.logger.warning("NetworkMonitor: لا توجد واجهة صالحة أو لا توجد قواعد مراقبة (منافذ مشبوهة/ICMP مفعل). سيتم تعطيل مراقبة الشبكة.")
             self.interface_name = None # تعطيل المراقبة فعلياً إذا لم يكن هناك ما يجب مراقبته


    # قراءة وتكوين إعدادات الشبكة من ملف الإعدادات
    def _configure(self):
        """يقرأ إعدادات واجهة الشبكة، المنافذ المشبوهة، والـ IP الموثوقة من ملف الإعدادات."""
        try:
            # قراءة إعدادات المنافذ المشبوهة
            ports_str = self.config.get('NIDS', 'SUSPICIOUS_PORTS', fallback='')
            # تحويل قائمة المنافذ إلى مجموعة من الأعداد الصحيحة
            self.suspicious_ports = {int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()}
            if not self.suspicious_ports:
                 self.logger.logger.warning("NetworkMonitor: قائمة المنافذ المشبوهة [NIDS]SUSPICIOUS_PORTS فارغة أو غير صالحة.")
            else:
                 self.logger.logger.info(f"NetworkMonitor: المنافذ المشبوهة للمراقبة: {sorted(list(self.suspicious_ports))}") # عرض المنافذ مرتبة

            # قراءة إعداد مراقبة ICMP Ping
            try:
                self._monitor_icmp_ping = self.config.getboolean('NIDS', 'MONITOR_ICMP_PING', fallback=False)
            except ValueError:
                self.logger.logger.error("NetworkMonitor: قيمة 'MONITOR_ICMP_PING' في [NIDS] يجب أن تكون 'yes' أو 'no'. استخدام القيمة الافتراضية False.")
                self._monitor_icmp_ping = False

            if self._monitor_icmp_ping:
                self.logger.logger.info("NetworkMonitor: تم تفعيل مراقبة ICMP Ping.")
            else:
                 self.logger.logger.info("NetworkMonitor: تم تعطيل مراقبة ICMP Ping.")


            # قراءة عناوين IP الموثوقة (Whitelist)
            ips_str = self.config.get('NETWORK', 'WHITELIST_IPS', fallback='')
            self.whitelist_ips = {ip.strip() for ip in ips_str.split(',') if ip.strip()}
            self.logger.logger.info(f"NetworkMonitor: عناوين IP الموثوقة: {self.whitelist_ips or 'لا يوجد'}")

            # قراءة واجهة الشبكة المحددة في الإعدادات
            config_interface = self.config.get('NETWORK', 'INTERFACE', fallback='').strip()
            available_interfaces = []
            try:
                # الحصول على قائمة الواجهات المتاحة بواسطة Scapy
                available_interfaces = get_if_list()
                self.logger.logger.info(f"NetworkMonitor: واجهات الشبكة المتاحة بواسطة Scapy: {available_interfaces}")
            except Exception as e:
                 self.logger.logger.error(f"NetworkMonitor: خطأ في جلب قائمة الواجهات بواسطة Scapy: {e}. قد تحتاج صلاحيات root.")


            # اختيار الواجهة للمراقبة: المفضلة هي المحددة في الإعدادات، ثم الاكتشاف التلقائي
            if config_interface and config_interface in available_interfaces:
                self.interface_name = config_interface
                self.logger.logger.info(f"NetworkMonitor: استخدام الواجهة المحددة في الإعدادات: {self.interface_name}")
            elif available_interfaces: # محاولة اختيار واجهة مناسبة تلقائياً إذا كانت هناك واجهات متاحة
                 # تجنب واجهات loopback (مثل 'lo') وعناوين loopback ('127.0.0.1', '::1')
                 default_iface = next((iface for iface in available_interfaces if 'lo' not in iface.lower() and 'loopback' not in iface.lower() and get_if_addr(iface) not in ['127.0.0.1', '::1']), None)

                 if default_iface:
                     self.interface_name = default_iface
                     if config_interface: # إذا كان المستخدم قد حدد واجهة خاطئة
                         self.logger.logger.warning(f"NetworkMonitor: الواجهة '{config_interface}' غير صالحة/غير موجودة. استخدام: {self.interface_name} (تلقائي).")
                     else: # إذا لم يحدد المستخدم واجهة
                         self.logger.logger.info(f"NetworkMonitor: لم يتم تحديد واجهة. استخدام الواجهة الافتراضية المناسبة: {self.interface_name}.")
                 elif available_interfaces: # إذا لم يتم العثور على واجهة غير loopback، استخدم الأولى المتاحة كحل أخير
                      self.interface_name = available_interfaces[0]
                      self.logger.logger.warning(f"NetworkMonitor: لم يتم العثور على واجهة غير loopback. استخدام الواجهة الأولى المتاحة: {self.interface_name}.")
                 else: # لا توجد واجهات متاحة على الإطلاق (حالة نادرة)
                      self.logger.logger.error("NetworkMonitor: لا يمكن العثور على أي واجهات شبكة متاحة بواسطة Scapy.")
                      self.interface_name = None
            else: # قائمة الواجهات المتاحة فارغة أو حدث خطأ سابق في جلبها
                 self.logger.logger.error("NetworkMonitor: لا توجد واجهات شبكة متاحة للمراقبة.")
                 self.interface_name = None

        except Exception as e:
            self.logger.logger.error(f"NetworkMonitor: خطأ أثناء قراءة إعدادات الشبكة أو تحديد الواجهة: {e}", exc_info=True)
            self.interface_name = None # تعطيل المراقبة في حالة وجود خطأ فادح في التهيئة


    # التحقق من صلاحيات التشغيل (خاصة root على Linux)
    def _is_privileged(self):
        """يتحقق مما إذا كان السكربت يعمل بالصلاحيات اللازمة لالتقاط الشبكة."""
        if platform.system() == "Windows":
            # على Windows، Scapy تتطلب Npcap وغالباً صلاحيات المسؤول.
            # التحقق الدقيق من الصلاحيات معقد. نصدر تحذيراً ونفترض أن المستخدم سيحاول بصلاحيات المسؤول.
            # دالة sniff ستفشل على الأرجح إذا لم تكن الصلاحيات كافية.
            self.logger.logger.warning("NetworkMonitor: على Windows، تأكد من تشغيل البرنامج 'كمسؤول'.")
            return True # افتراض محاولة المستخدم بصلاحيات كافية
        elif platform.system() == "Linux":
             try:
                  is_root = (os.geteuid() == 0) # os.geteuid() تعيد معرف المستخدم الفعلي (0 لـ root)
                  if not is_root:
                       self.logger.logger.warning("NetworkMonitor: على Linux، يجب تشغيل البرنامج بصلاحيات root (sudo) لالتقاط حزم الشبكة باستخدام Scapy.")
                  return is_root
             except AttributeError:
                  # os.geteuid قد لا تكون متاحة على بعض المنصات (نادر جداً على Linux)
                  self.logger.logger.warning("NetworkMonitor: لم يتمكن من التحقق من صلاحيات root باستخدام os.geteuid.")
                  return True # لا يمكن التحقق، نفترض أن المستخدم يتعامل مع الصلاحيات
        else:
            # أنظمة تشغيل أخرى
            self.logger.logger.warning(f"NetworkMonitor: لا يمكن التحقق من الصلاحيات على نظام التشغيل {platform.system()}. تأكد من تشغيل البرنامج بالصلاحيات اللازمة للتقاط الشبكة.")
            return True # لا يمكن التحقق، نفترض أن المستخدم يتعامل مع الصلاحيات


    # معالج حزم الشبكة
    def _packet_handler(self, packet):
        """تتم استدعاء هذه الدالة لكل حزمة يتم التقاطها."""
        try:
            # يجب أن تكون الحزمة من نوع IP للتحقق من المصدر والوجهة
            if not IP or not packet.haslayer(IP):
                 return

            src_ip = packet[IP].src # عنوان IP المصدر
            dst_ip = packet[IP].dst # عنوان IP الوجهة

            # تجاهل الحزم إذا كان أي من عنواني IP المصدر أو الوجهة في القائمة الموثوقة
            if src_ip in self.whitelist_ips or dst_ip in self.whitelist_ips:
                 return

            alert_message = None # رسالة التنبيه المراد تسجيلها
            alert_key = None     # مفتاح لـ recent_alerts_cache لتتبع التنبيهات المكررة
            proto = None         # بروتوكول الطبقة الرابعة (TCP/UDP/ICMP)

            # --- التحقق من المنافذ المشبوهة لبروتوكولات TCP و UDP ---
            if (TCP and packet.haslayer(TCP)) or (UDP and packet.haslayer(UDP)):
                # تحديد البروتوكول والطبقة
                if packet.haslayer(TCP):
                    proto = "TCP"
                    layer = packet[TCP]
                else:
                    proto = "UDP"
                    layer = packet[UDP]

                src_port = layer.sport # منفذ المصدر
                dst_port = layer.dport # منفذ الوجهة

                # التحقق مما إذا كان أي من المنفذين في قائمة المنافذ المشبوهة
                if src_port in self.suspicious_ports or dst_port in self.suspicious_ports:
                    # تحديد المنفذ المشبوه الذي تم العثور عليه في الحزمة
                    suspicious_port_found = dst_port if dst_port in self.suspicious_ports else src_port
                    # بناء رسالة التنبيه
                    alert_message = (f"اتصال {proto} على منفذ مشبوه ({suspicious_port_found}): "
                                     f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    # بناء مفتاح فريد لهذا التنبيه للذاكرة المؤقتة
                    alert_key = f"{proto}-{src_ip}:{src_port}-{dst_ip}:{dst_port}"

            # --- التحقق من حزم ICMP Ping إذا كانت المراقبة مفعلة ---
            elif self._monitor_icmp_ping and ICMP and packet.haslayer(ICMP):
                 icmp_type = packet[ICMP].type # نوع ICMP
                 # ICMP Type 8 هو Echo Request (طلب Ping)
                 # ICMP Type 0 هو Echo Reply (رد Ping)
                 if icmp_type == 8 or icmp_type == 0:
                      proto = "ICMP"
                      # تحديد وصف نوع ICMP
                      icmp_desc = "Echo Request" if icmp_type == 8 else "Echo Reply"
                      # بناء رسالة التنبيه
                      alert_message = (f"كشف حزمة ICMP Ping ({icmp_desc}, Type: {icmp_type}) "
                                       f"من {src_ip} إلى {dst_ip}")
                      # بناء مفتاح فريد لهذا التنبيه لـ ICMP (لا توجد منافذ)
                      alert_key = f"ICMP-{icmp_type}-{src_ip}-{dst_ip}"


            # --- تسجيل التنبيه إذا تم توليده ولم يتم تسجيله مؤخراً ---
            if alert_message and alert_key:
                now = time.time() # الوقت الحالي (timestamp)

                # استخدام القفل لحماية الوصول إلى ذاكرة التنبيهات المؤقتة
                with self.recent_alerts_lock:
                    # تنظيف الإدخالات القديمة في الذاكرة المؤقتة التي تجاوزت مدة الانتهاء
                    expired_keys = [k for k, ts in self.recent_alerts_cache.items() if now - ts > self.alert_cache_expiry]
                    for k in expired_keys:
                        del self.recent_alerts_cache[k]

                    # إذا لم يكن مفتاح التنبيه موجوداً في الذاكرة المؤقتة (أي لم يتم التنبيه عليه مؤخراً)
                    if alert_key not in self.recent_alerts_cache:
                        # سجل التنبيه باستخدام دالة log_alert
                        self.logger.log_alert('NIDS_ALERT', alert_message, 'NetworkMonitor', proto=proto)
                        # إضافة التنبيه الحالي إلى الذاكرة المؤقتة مع وقته الحالي
                        self.recent_alerts_cache[alert_key] = now

        except Exception as e:
            # تسجيل أي خطأ يحدث أثناء معالجة حزمة معينة (معلومات الخطأ محدودة لتجنب الفيضان)
            # exc_info=False لتجنب طباعة traceback الكامل لكل خطأ حزمة
            self.logger.logger.error(f"NetworkMonitor: خطأ بمعالجة الحزمة: {e}", exc_info=False)


    # حلقة التقاط الحزم باستخدام Scapy
    def _sniff_loop(self):
        """الحلقة الرئيسية التي تقوم بالتقاط الحزم."""
        # تحقق مرة أخرى من أن الواجهة صالحة قبل بدء التقاط
        if not self.interface_name:
            self.logger.logger.error("NetworkMonitor: لا يمكن بدء التقاط الحزم، لا يوجد واجهة شبكة صالحة.")
            self.running.clear() # تأكد من مسح علامة التشغيل إذا لم نتمكن من البدء
            return

        self.logger.logger.info(f"NetworkMonitor: بدء التقاط الحزم على الواجهة '{self.interface_name}'...")
        try:
            # دالة sniff من Scapy تقوم بالتقاط الحزم بشكل غير توقفي (Non-blocking) إذا تم تحديد stop_filter
            sniff(
                iface=self.interface_name, # واجهة الشبكة التي سيتم التقاط الحزم منها
                prn=self._packet_handler, # الدالة التي سيتم استدعاؤها لكل حزمة
                store=0, # لا تقم بتخزين الحزم في الذاكرة (لتجنب استهلاك الذاكرة)
                stop_filter=lambda p: not self.running.is_set() # دالة تتوقف عندها sniff (عندما تكون running Event غير مضبوطة)
            )
            # إذا وصلت نقطة التنفيذ إلى هنا، فهذا يعني أن sniff توقفت.
            # إذا كانت running Event لا تزال مضبوطة، فهذا يعني أنها توقفت بشكل غير متوقع.
            if self.running.is_set():
                 self.logger.logger.warning("NetworkMonitor: حلقة التقاط الحزم توقفت بشكل غير متوقع.")
        # معالجة الأخطاء الشائعة مثل عدم وجود الواجهة أو نقص الصلاحيات
        except OSError as e:
             self.logger.logger.error(f"NetworkMonitor: خطأ OSError بالتقاط الحزم على '{self.interface_name}'. "
                                     f"تأكد من الصلاحيات (sudo) وأن الواجهة صحيحة. الخطأ: {e}")
        except Exception as e:
             self.logger.logger.error(f"NetworkMonitor: خطأ غير متوقع بحلقة التقاط الحزم: {e}", exc_info=True)
        finally:
             # تأكد من مسح علامة التشغيل في النهاية بغض النظر عن سبب توقف sniff
             self.running.clear()
             self.logger.logger.info("NetworkMonitor: حلقة التقاط الحزم انتهت.")


    # بدء خيط مراقبة الشبكة
    def start(self):
        """يبدأ خيط التقاط الحزم إذا كانت Scapy متاحة والإعدادات صحيحة."""
        if not SCAPY_AVAILABLE:
             self.logger.logger.error("NetworkMonitor: لا يمكن البدء، Scapy غير متاحة.")
             return
        # يتم فحص interface_name وقواعد المراقبة في __init__، إذا كانت غير صالحة، فالمراقبة معطلة فعلياً.
        if not self.interface_name:
             self.logger.logger.error("NetworkMonitor: لا يمكن البدء، لم يتم تهيئة واجهة شبكة صالحة أو لا توجد قواعد مراقبة.")
             return

        # فحص حاسم لصلاحيات root قبل بدء التقاط الحزم
        if not self._is_privileged():
             # _is_privileged تقوم بالفعل بتسجيل تحذير مناسب
             self.logger.logger.error("NetworkMonitor: لا يمكن بدء المراقبة بدون الصلاحيات اللازمة (root/sudo).")
             return

        # بدء الخيط فقط إذا لم يكن يعمل بالفعل
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.running.set() # ضبط Event لبدء الحلقة
            # إنشاء الخيط وتحديد الدالة الهدف واسم الخيط وجعله Daemon
            self.monitor_thread = threading.Thread(target=self._sniff_loop, name="NetworkMonitorThread", daemon=True)
            self.monitor_thread.start() # بدء الخيط
            self.logger.logger.info("NetworkMonitor: تم بدء خيط مراقبة الشبكة.")

    # إيقاف خيط مراقبة الشبكة
    def stop(self):
        """يطلب إيقاف خيط التقاط الحزم وينتظر إكماله."""
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.logger.logger.info("NetworkMonitor: طلب إيقاف خيط مراقبة الشبكة...")
            self.running.clear() # مسح Event لإيقاف حلقة sniff
            # الانتظار حتى ينتهي الخيط بمهلة
            self.monitor_thread.join(timeout=5.0)
            if not self.monitor_thread.is_alive():
                self.logger.logger.info("NetworkMonitor: تم إيقاف خيط مراقبة الشبكة بنجاح.")
            else:
                self.logger.logger.warning("NetworkMonitor: خيط مراقبة الشبكة لم يتوقف ضمن المهلة المحددة.")
        self.monitor_thread = None # إعادة تعيين الكائن بعد الإيقاف


# --- إعدادات المصادقة وواجهة الويب (Flask) ---

# دالة للتحقق من اسم المستخدم وكلمة المرور للمصادقة الأساسية
@auth.verify_password         
def verify_password(username, password):
    current_logger = logging.getLogger('IDS') # الحصول على logger لاستخدامه داخل الدالة
    try:
        # قراءة اسم المستخدم وكلمة المرور من ملف الإعدادات
        stored_username = config.get('WEB', 'USERNAME')
        stored_pw = config.get('WEB', 'PASSWORD')

        # التحقق من اسم المستخدم
        if username == stored_username:
            # التحقق مما إذا كانت كلمة المرور المخزنة هي تجزئة (Hash)
            if stored_pw.startswith(('pbkdf2-sha256$', 'scrypt$')):
                try:
                    # استخدام check_password_hash للمقارنة الآمنة مع التجزئة
                    return check_password_hash(stored_pw, password)
                except Exception as e:
                    current_logger.error(f"خطأ بتحقق تجزئة كلمة المرور: {e}")
                    return False # فشل التحقق بسبب خطأ في التجزئة
            else:
                 # تحذير إذا كانت كلمة المرور مخزنة كنص عادي (غير آمن!)
                 if stored_pw != password:
                      current_logger.warning(f"فشل محاولة دخول للمستخدم '{username}' (استخدام كلمة مرور كنص عادي).")
                 return stored_pw == password # مقارنة مباشرة للنص العادي
        else:
            current_logger.warning(f"فشل محاولة دخول (اسم مستخدم خاطئ): '{username}'.")
    except Exception as e:
        current_logger.error(f"خطأ في دالة verify_password: {e}")
        return False # فشل المصادقة بسبب خطأ عام
    return False # فشل المصادقة في جميع الحالات الأخرى

# معالج الخطأ للمصادقة (يتم استدعاؤه عند فشل verify_password)
@auth.error_handler
def auth_error():
    # يعيد استجابة 401 Unauthorized ليطلب المتصفح بيانات المصادقة
    return "Unauthorized Access", 401

# المسار الرئيسي (الصفحة الرئيسية) لواجهة الويب
@app.route('/')
@auth.login_required # يتطلب مصادقة للوصول إلى هذا المسار
def dashboard():
    try:
        # يعرض قالب dashboard.html
        return render_template('dashboard.html')
    except Exception as e:
         logging.getLogger('IDS').error(f"خطأ بعرض قالب لوحة التحكم: {e}", exc_info=True)
         return "خطأ داخلي بالخادم عند تحميل لوحة التحكم.", 500
# الواجهة البرمجية (API) لجلب التنبيهات
@app.route('/api/alerts')
@auth.login_required # يتطلب مصادقة للوصول إلى هذا المسار أيضاً
def get_alerts():
    alerts_list = [] # قائمة لتخزين التنبيهات قبل إرسالها كـ JSON
    current_logger = ids_logger.logger if 'ids_logger' in globals() and ids_logger else logging.getLogger('IDS') # الحصول على logger

    try:
        conn = ids_logger.conn # الحصول على اتصال قاعدة البيانات
        conn.row_factory = sqlite3.Row # لتمكين الوصول إلى الصفوف كقاموس
        cur = conn.cursor() # الحصول على مؤشر قاعدة البيانات

        # تنفيذ استعلام لجلب آخر 50 تنبيهاً (مع عمود البروتوكول)
        cur.execute("SELECT id, type, source, message, strftime('%Y-%m-%d %H:%M:%S', timestamp) as timestamp, proto FROM alerts ORDER BY id DESC LIMIT 50")
        # تحويل الصفوف المسترجعة إلى قائمة من القواميس
        alerts_list = [dict(row) for row in cur.fetchall()]
        cur.close() # إغلاق المؤشر

    except Exception as e:
         current_logger.error(f"خطأ بجلب التنبيهات من قاعدة البيانات: {e}", exc_info=True)
         # إعادة استجابة خطأ بصيغة JSON
         return jsonify({"error": "خطأ باسترداد التنبيهات من قاعدة البيانات"}), 500

    # إعادة قائمة التنبيهات بصيغة JSON
    return jsonify(alerts_list)


# --- نقطة البداية الرئيسية لتشغيل السكربت ---
if __name__ == '__main__':
    # التحقق من صلاحيات root مبكراً على لينكس لتقديم تحذير واضح
    if platform.system() == 'Linux':
        if os.geteuid() != 0:
            print("="*60)
            print("تحذير: يتم تشغيل نظام IDS بدون صلاحيات root.")
            print("مراقبة الشبكة (NIDS) والكتابة لمسارات السجل/قاعدة البيانات في النظام")
            print("قد لا تعمل بشكل صحيح دون صلاحيات root (sudo).")
            print("الرجاء تشغيل السكربت باستخدام sudo (مثال: sudo python3 ids.py).")
            print("="*60)
        # ملاحظة: السكربت يستمر بالعمل حتى بدون root للسماح بتشغيل مكونات HIDS التي لا تحتاج صلاحيات عالية،
        # ولكن NIDS وميزات التسجيل في مسارات النظام ستفشل.
    # تهيئة نظام التسجيل وقاعدة البيانات أولاً
    try:
        ids_logger = IDSLogger()
        logger = ids_logger.logger # الحصول على logger للاستخدام العام في السكربت
    except Exception as e:
        print(f"فشل فادح في تهيئة التسجيل أو قاعدة البيانات: {e}")
        sys.exit(1)
# --- عرض فن ASCII المدمج لبدء التشغيل ---
    # نولد اللافتة. نستخدم alert=False لأنها لافتة بدء تشغيل ثابتة في هذه النقطة.
    startup_banner_text = generate_startup_banner(alert=False)
    print("\n")
    print(startup_banner_text)
    print("\n")
    print(f"{Colors.BOLD}{Colors.BLUE}##############################################################################################{Colors.RESET}")
    print("\n")
    # رسائل بدء النظام في السجل والطرفية
    logger.info("="*60)
    logger.info("     بدء تشغيل نظام كشف التسلل (IDS)               ")
    logger.info("="*60)
    logger.info(f"الإعدادات من: {os.path.abspath(config_path)}")
    logger.info(f"قاعدة البيانات: {ids_logger.db_path.resolve()}") # resolve() للحصول على المسار المطلق النهائي
    logger.info(f"ملف السجل: {ids_logger.log_path.resolve()}")

    # عرض حالة مكونات HIDS و NIDS بناءً على الإعدادات وتوفر Scapy
    logger.info(f"الملفات المراقبة (HIDS): {AppConfig.SENSITIVE_FILES or 'لا يوجد'}")
    logger.info(f"العمليات المشبوهة المراقبة (HIDS): {config.get('HIDS','SUSPICIOUS_PROCS', fallback='لا يوجد')}")
    if SCAPY_AVAILABLE:
        logger.info(f"المنافذ المشبوهة للمراقبة (NIDS): {config.get('NIDS','SUSPICIOUS_PORTS', fallback='لا يوجد')}")
        logger.info(f"مراقبة ICMP Ping (NIDS): {'مفعل' if config.getboolean('NIDS', 'MONITOR_ICMP_PING', fallback=False) else 'معطل'}")
        logger.info(f"واجهة الشبكة المحددة (NIDS): {config.get('NETWORK','INTERFACE', fallback='تلقائي')}")
        logger.info(f"عناوين IP الموثوقة (NIDS): {config.get('NETWORK', 'WHITELIST_IPS', fallback='لا يوجد')}")
    else:
        logger.warning("مراقبة الشبكة (NIDS) معطلة: مكتبة Scapy غير متاحة.")

    logger.info("---------------------------------------------------")
    # تسجيل حدث بدء النظام كتنبيه
    ids_logger.log_alert("SYSTEM_INFO", "تم بدء نظام كشف التسلل.", "IDS_Core")
    # --- بدء مكونات المراقبة ---

    # بدء مراقب الملفات (HIDS)
    file_monitor = FileMonitor(ids_logger)
    monitor_observer = file_monitor.start() # start() تعيد observer إذا بدأت بنجاح
    # بدء مراقب العمليات (HIDS)
    process_monitor = ProcessMonitor(ids_logger, config)
    process_monitor.start()
    # بدء مراقب الشبكة (NIDS) إذا كانت Scapy متاحة وتم تهيئتها
    network_monitor = None
    if SCAPY_AVAILABLE:
        # يتم التحقق من الواجهة وقواعد المراقبة والصلاحيات داخل NetworkMonitor.__init__ و start()
        network_monitor = NetworkMonitor(ids_logger, config)
        network_monitor.start()
    else:
        # تسجيل تحذير إذا لم يتم تفعيل NIDS بسبب Scapy
        ids_logger.log_alert("SYSTEM_WARNING", "مراقبة الشبكة (NIDS) معطلة بسبب عدم توفر Scapy.", "IDS_Core")


    # --- بدء خادم الويب ---
    web_host = config.get('WEB', 'HOST', fallback='127.0.0.1')
    web_port = config.getint('WEB', 'PORT', fallback=5000)

    logger.info(f"بدء خادم الويب على http://{web_host}:{web_port}")
    logger.info("اضغط Ctrl+C لإيقاف النظام.")

    server_thread = None
    try:
        # نحاول استخدام خادم waitress الإنتاجي أولاً إذا كان مثبتاً
        try:
            from waitress import serve
            # تشغيل خادم Waitress في خيط منفصل
            server_thread = threading.Thread(target=serve, args=(app,), kwargs={'host': web_host, 'port': web_port, 'threads': 8, '_quiet': True}, name="WebServerThread", daemon=True)
            server_thread.start()
            logger.info("تم تشغيل خادم Waitress.")
        except ImportError:
             # إذا لم تكن waitress مثبتة، نعود لاستخدام خادم تطوير Flask المدمج
             logger.warning("مكتبة 'waitress' غير مثبتة. استخدام خادم تطوير Flask (غير مناسب للإنتاج).")
             # تشغيل خادم Flask في الخيط الرئيسي (blocking call)
             # يجب تعطيل debug و use_reloader لتجنب مشاكل تعدد الخيوط عند تشغيل مكونات أخرى
             app.run(host=web_host, port=web_port, threaded=True, debug=False, use_reloader=False)

        # إذا تم استخدام waitress (تشغيلها في خيط)، فإن الخيط الرئيسي يحتاج للبقاء قيد التشغيل
        if server_thread and server_thread.is_alive():
             while True:
                 # الخيط الرئيسي ببساطة ينتظر الإشارة للإيقاف
                 time.sleep(1)
    # --- التعامل مع إشارات الإيقاف ---
    # SystemExit يتم إطلاقها عادةً بواسطة sys.exit()
    except SystemExit:
        logger.info("تم طلب إنهاء النظام.")
    # KeyboardInterrupt يتم إطلاقها عند الضغط على Ctrl+C
    except KeyboardInterrupt:
        logger.info("تم طلب إنهاء (Ctrl+C).")
    except Exception as e:
        # أي خطأ فادح غير متوقع في الحلقة الرئيسية أو بدء الخادم
        logger.critical(f"فشل فادح بالخادم أو الحلقة الرئيسية: {e}", exc_info=True)

    # --- عملية الإيقاف النظيف (تنفذ دائماً في النهاية) ---
    finally:
        logger.info("="*60)
        logger.info("     بدء إيقاف نظام كشف التسلل...                 ")
        logger.info("="*60)
        # إيقاف مكونات المراقبة بترتيب منطقي (أو عكس ترتيب البدء)
        # إيقاف مراقب الشبكة أولاً لأنه قد يعتمد على موارد نظام حساسة
        if network_monitor:
            network_monitor.stop()
        # إيقاف مراقب العمليات
        if process_monitor:
            process_monitor.stop()
        # إيقاف مراقب الملفات (يحتاج للانضمام إلى خيط watchdog)
        if file_monitor and monitor_observer: # تأكد من أنه تم بدء المراقب بنجاح
             file_monitor.stop()
        # إغلاق اتصال قاعدة البيانات
        if ids_logger and hasattr(ids_logger, 'conn') and ids_logger.conn:
            try:
                ids_logger.conn.close()
                logger.info("تم إغلاق اتصال قاعدة البيانات.")
            except Exception as e:
                logger.error(f"خطأ بإغلاق قاعدة البيانات: {e}")
        logger.info("---------------------------------------------------")
        logger.info("            تم إيقاف نظام كشف التسلل.             ")
        logger.info("---------------------------------------------------")
