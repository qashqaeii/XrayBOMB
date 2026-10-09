# راهنمای تست مجدد (همراه اول / ایرانسل)

## وضعیت VPN

| سناریو | VPN دیگر | v2ray/XrayBOMB |
|--------|----------|----------------|
| A — baseline تمیز | **خاموش** | خاموش |
| B — مثل الان | روشن | روشن |
| C — فقط کانفیگ تحت تست | خاموش | فقط SOCKS تست XrayBOMB |

گزارش `test_environment` و `leak_check` را برای هر سنario جدا ذخیره کنید.

## مراحل

1. یک کانفیگ را Analyze کنید؛ `run_id` و `socks_port` در بخش Xray Test را یادداشت کنید.
2. سنario A را اجرا کنید و IP پایه را با IP خروجی (`exit_ip`) مقایسه کنید.
3. batch چهار کانفیگ: هر ردیف باید `socks_port` متفاوت و نتیجه مستقل داشته باشد.
4. export JSON را با `redact_secrets_export=true` بررسی کنید — UUID/لینک نباید باز باشد.

## محدودیت‌های باقی‌مانده

- `trust_env=False` پروکسی محیطی Python را دور می‌زند، نه TUN/VPN سطح OS.
- تست DNS leak واقعی هنوز **Not tested** است.
- REALITY/gRPC/QUIC از بیرون بدون xray-core احراز کامل نمی‌شوند.
- SSH read-only روی سرور خودتان: از پنل SSH موجود با دستورات فقط-خواندنی (`ss -lntp`, `systemctl status`) استفاده کنید؛ اتوماسیون جمع‌آوری در نسخه بعدی.
