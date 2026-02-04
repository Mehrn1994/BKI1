# 🌐 Network Config Portal - راهنمای نصب

## 📦 محتویات پکیج

```
├── server_database.py      # سرور اصلی
├── rebuild_database.py     # اسکریپت ساخت دیتابیس
├── templates/              # فایل‌های HTML
│   ├── index.html
│   ├── login.html
│   ├── intranet.html
│   ├── apn_int.html
│   ├── apn_mali.html
│   ├── reserve_lan.html
│   └── db_manager.html
└── excel_files/            # فایل‌های اکسل
    ├── Branch-Lan-IP.xlsx
    ├── Intranet.xlsx
    ├── IP_APN_WAN.xlsx
    ├── Tunnel_IP_Pair_APN_Mali.xlsx
    └── Tunnel200_IPs-APN-INT.xlsx
```

## 🔧 نصب

### مرحله 1: جایگزینی فایل‌ها

```cmd
cd C:\router-config-tool

# پشتیبان از فایل‌های قبلی
copy server_database.py server_database_backup.py
xcopy templates templates_backup /E /I

# جایگزینی فایل‌های جدید
copy /Y [مسیر دانلود]\server_database.py .
xcopy /Y /E [مسیر دانلود]\templates templates
xcopy /Y /E [مسیر دانلود]\excel_files excel_files
copy /Y [مسیر دانلود]\rebuild_database.py .
```

### مرحله 2: ساخت دیتابیس جدید

```cmd
cd C:\router-config-tool

# پشتیبان از دیتابیس قبلی
copy data\network_ipam.db data\network_ipam_backup.db

# ساخت دیتابیس جدید
python rebuild_database.py
```

خروجی باید چنین باشد:
```
✅ Tables created
✅ Imported 477 LAN IPs
✅ Imported 1157 Intranet Tunnels
✅ Imported 738 APN Mali IPs
✅ Imported 247 APN INT IPs
✅ Imported 627 Tunnel Mali pairs
✅ Imported 42 Tunnel200 pairs
✅ Database rebuild complete!
```

### مرحله 3: اجرای سرور

```cmd
python server_database.py
```

## 📊 داده‌های موجود

| جدول | تعداد | Free |
|------|-------|------|
| LAN IPs | 477 | 477 |
| Intranet Tunnels | 1157 | 92 |
| APN غیرمالی | 247 | 247 |
| APN مالی | 738 | 735 |
| Tunnel Mali | 627 | 627 |
| Tunnel200 | 42 | 42 |

## 🔐 دسترسی‌ها

- **مدیریت دیتابیس**: فقط کاربر `Sahebdel` دسترسی دارد
- **سایر صفحات**: همه کاربران مجاز دسترسی دارند

## ⚠️ نکات مهم

1. **قبل از نصب حتماً از دیتابیس پشتیبان بگیرید**
2. بعد از هر رزرو، دیتابیس به صورت خودکار بروزرسانی می‌شود
3. رزروهای IP LAN بعد از 60 روز منقضی می‌شوند

## 🐛 عیب‌یابی

اگر "هیچ IP آزادی موجود نیست" دیدید:
1. مطمئن شوید `rebuild_database.py` اجرا شده
2. مطمئن شوید فایل‌های اکسل در پوشه `excel_files` هستند
3. سرور را restart کنید

---
تاریخ: 2026-02-04

salam
