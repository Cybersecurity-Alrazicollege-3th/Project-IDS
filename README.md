# Project-IDS

#!/bin/bash
# نظام كشف التسلل البسيط باستخدام Bash
# هذا السكربت يقدم وظائف مراقبة أساسية جداً (وجود ملف، أسماء عمليات).
# لا يمثل بديلاً كاملاً لنسخة Python الأكثر تقدماً.

# مسار ملف الإعدادات
CONFIG_FILE="./ids_config.sh"

# التحقق من وجود ملف الإعدادات واستدعائه (sourcing)
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "خطأ: ملف الإعدادات '$CONFIG_FILE' غير موجود."
    exit 1
fi

# التحقق مما إذا كان مسار السجل يحتوي على اسم ملف
if [ -z "$(basename "$LOG_FILE")" ] || [ "$(basename "$LOG_FILE")" == "." ]; then
    echo "خطأ: مسار ملف السجل غير صالح. يرجى تحديد اسم ملف في LOG_FILE."
    exit 1
fi

# التحقق من وجود مجلد السجل وإنشائه إذا لم يكن موجوداً
LOG_DIR=$(dirname "$LOG_FILE")
if [ ! -d "$LOG_DIR" ]; then
    echo "مجلد السجل '$LOG_DIR' غير موجود، جاري الإنشاء..."
    mkdir -p "$LOG_DIR"
    # التحقق من نجاح الإنشاء (يتطلب صلاحيات إذا كان المسار يتطلب ذلك مثل /var/log)
    if [ $? -ne 0 ]; then
        echo "خطأ: فشل في إنشاء مجلد السجل '$LOG_DIR'. يرجى التحقق من الصلاحيات."
        exit 1
    fi
fi

# دالة لتسجيل التنبيهات في ملف السجل وعلى الشاشة
log_alert() {
    local type="$1"    # نوع التنبيه (مثال: HIDS_ALERT, SYSTEM_INFO)
    local source="$2"  # مصدر التنبيه (مثال: FileMonitor, ProcessMonitor)
    local message="$3" # رسالة التنبيه
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S") # الوقت الحالي

    # تنسيق رسالة السجل
    log_message="$timestamp - [$type] - [$source] - $message"

    # طباعة الرسالة على الشاشة وحفظها في ملف السجل
    echo "$log_message" | tee -a "$LOG_FILE"
    # 'tee -a' يقوم بالطباعة على الشاشة (-a) وإضافة إلى ملف السجل (-a)
}

# --- HIDS: File Existence Check ---
check_sensitive_files() {
    # رسالة معلومات لبدء الفحص - يمكن تعطيل هذه الرسائل المتكررة للسجل النصي إذا كانت مزعجة
    # log_alert "HIDS_CHECK" "FileMonitor" "بدء فحص وجود الملفات الحساسة."

    # المرور على كل ملف في قائمة SENSITIVE_FILES
    for file_path in "${SENSITIVE_FILES[@]}"; do
        # التحقق مما إذا كان الملف غير موجود ('! -f')
        if [ ! -f "$file_path" ]; then
            # إذا كان الملف غير موجود، سجل تنبيه
            log_alert "HIDS_ALERT" "FileMonitor" "لم يتم العثور على ملف حساس (قد يكون محذوفاً أو تمت إعادة تسميته): $file_path"
        # Note: Bash cannot easily check for modifications or new files in sensitive directories
        # without complex logic or external tools like inotifywait.
        fi
    done
    # To check for *new* files in sensitive directories, it would require
    # storing a list of known files and comparing, or using inotifywait.
    # This simple script only checks if the pre-configured sensitive files *exist*.
}

# --- HIDS: Process Name Check ---
check_suspicious_processes() {
    # رسالة معلومات لبدء الفحص - يمكن تعطيل هذه الرسائل المتكررة للسجل النصي إذا كانت مزعجة
    # log_alert "HIDS_CHECK" "ProcessMonitor" "بدء فحص العمليات المشبوهة."

    # استخدام ps للحصول على قائمة العمليات مع المستخدم والمعرف والأمر
    # ps -ef هو تنسيق قياسي يسهل قراءته
    # تخزين الناتج في متغير لتجنب استدعاء ps عدة مرات
    PS_OUTPUT=$(ps -ef 2>/dev/null) # إعادة توجيه خطأ الصلاحيات إن وجد

    # المرور على كل اسم عملية مشبوهة في القائمة
    for proc_name in "${SUSPICIOUS_PROCS[@]}"; do
        # استخدام grep للبحث عن اسم العملية (بحث غير حساس لحالة الأحرف -i)
        # [${proc_name:0:1}]${proc_name:1} هي حيلة للبحث عن العملية نفسها وتجنب العثور على أمر grep نفسه
        # awk لاستخراج معلومات المستخدم ($1)، الـ PID ($2)، والأمر كاملاً ($8 فما بعد)
        # read -r يقرأ كل سطر كإدخال واحد لتجنب تقسيم الأسطور التي تحتوي على مسافات
        echo "$PS_OUTPUT" | grep -i "[${proc_name:0:1}]${proc_name:1}" | awk '{print "PID:" $2 ", User:" $1 ", Cmd:" substr($0, index($0,$8))}' | while read -r proc_info; do
            # سجل تنبيه لكل عملية مشبوهة تم العثور عليها
            # ملاحظة: هذا السكربت لا يتتبع الـ PIDs المسجلة مسبقاً،
            # لذا قد يسجل نفس التنبيه للعملية نفسها في كل دورة فحص طالما أنها تعمل.
            log_alert "HIDS_ALERT" "ProcessMonitor" "تم العثور على عملية مشبوهة: $proc_info (الاسم يطابق: $proc_name)"
        done
    done
}

# --- Cleanup Function (Executed on SIGINT) ---
# دالة سيتم تنفيذها عند استقبال إشارة الإنهاء (مثل Ctrl+C)
cleanup() {
    log_alert "SYSTEM_INFO" "BashIDS" "تم استقبال إشارة الإنهاء (Ctrl+C)."
    log_alert "SYSTEM_INFO" "BashIDS" "جاري إيقاف نظام Bash IDS البسيط."
    exit 0 # الخروج من السكربت بنجاح
}

# --- Trap SIGINT signal ---
# إعداد أمر trap لاستدعاء دالة cleanup عند استقبال SIGINT
trap 'cleanup' SIGINT

# --- الحلقة الرئيسية للمراقبة ---

# رسائل بدء النظام
log_alert "SYSTEM_INFO" "BashIDS" "تم بدء نظام Bash IDS البسيط."
log_alert "SYSTEM_INFO" "BashIDS" "ملف السجل: $LOG_FILE"
log_alert "SYSTEM_INFO" "BashIDS" "الفاصل الزمني للفحص: $CHECK_INTERVAL ثانية"
log_alert "SYSTEM_INFO" "BashIDS" "الملفات الحساسة التي يتم فحص وجودها: ${SENSITIVE_FILES[*]}"
log_alert "SYSTEM_INFO" "BashIDS" "العمليات المشبوهة التي يتم البحث عنها: ${SUSPICIOUS_PROCS[*]}"
log_alert "SYSTEM_WARNING" "BashIDS" "هذا الإصدار لا يتضمن مراقبة الشبكة (NIDS) أو واجهة الويب أو قاعدة بيانات."
log_alert "SYSTEM_INFO" "BashIDS" "اضغط Ctrl+C لإيقاف النظام بشكل آمن." # Updated message

# حلقة لا نهائية لتكرار الفحوصات
while true; do
    # استدعاء دالة فحص الملفات
    check_sensitive_files

    # استدعاء دالة فحص العمليات
    check_suspicious_processes

    # رسالة معلومات قبل فترة الانتظار
    # log_alert "SYSTEM_INFO" "BashIDS" "النوم لمدة $CHECK_INTERVAL ثواني..." # Optional: uncomment if you want sleep messages in the log

    # الانتظار للمدة المحددة
    sleep "$CHECK_INTERVAL"
done

# ملاحظة: الدالة cleanup ستتعامل مع الخروج عند الضغط على Ctrl+C.
