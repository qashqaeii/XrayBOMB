# تست دستی پس از دریافت تغییرات

## قبل از Analyze

1. **V2Ray و Proxifier را خاموش کنید** (و در صورت امکان VPN سیستم).
2. در تنظیمات برنامه: `Run Xray Test` و در صورت نیاز `Real Proxy Test` را روشن بگذارید.

## حین Analyze

- در تب **Xray Test**: `run_id`، `Internet E2E`، `Baseline` و `IP Leak` را ببینید.
- در تب **Connection Architecture**: سناریوها، شواهد موافق/مخالف و تفاوت probe بیرونی با E2E.
- `IP Leak = Unknown` در baseline نامطمئن **طبیعی** است؛ False به‌معنی «قطعی بدون نشت» نیست.

## خروجی JSON پاک‌سازی‌شده برای اشتراک

- منوی Export → JSON (تنظیم `redact_secrets_export` در Settings فعال باشد).
- Batch: `BatchReportExporter.to_json()` همان redaction را اعمال می‌کند.
- Cloud Sync نیز در صورت فعال بودن redaction، payload پالایش‌شده می‌فرستد.

## سناریوهای پیشنهادی

| # | هدف |
|---|-----|
| 1 | یک کانفیگ با VPN/Proxifier **خاموش** — baseline تمیز |
| 2 | همان کانفیگ با Proxifier روشن — مقایسه baseline_inconclusive |
| 3 | Batch ۴ کانفیگ — `socks_port` و `run_id` مستقل |
| 4 | `real_proxy_test=False` — فقط `xray -test`، بدون ادعای اینترنت |
