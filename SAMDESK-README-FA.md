# SamDesk — سورس شخصی‌سازی‌شده RustDesk 1.5.1

تغییرات اعمال‌شده (فقط این‌ها):
- `libs/hbb_common/src/config.rs`: سرور = 94.184.45.61 ، کلید عمومی = RhBjARpUs1S9xCFez2foZBFGWqyTVvStd+fyAYgn2w8= ، نام برنامه = SamDesk
- `Cargo.toml`: نام محصول و توضیحات ویندوز

کلید خصوصی در هیچ جای این پروژه نیست.

## بیلد روی GitHub Actions (رایگان برای ریپوی public)
1. روی github.com یک ریپوی جدید بساز (مثلاً samdesk-client) و محتویات این zip رو داخلش آپلود کن
   (یا با git: git init، git add -A، git commit، git remote add origin ...، git push).
2. تب Actions رو فعال کن، workflow با اسم "Flutter Nightly Build" رو دستی (Run workflow) اجرا کن.
3. بعد از ۴۰ تا ۹۰ دقیقه، از بخش Artifacts / Releases فایل‌های ویندوز رو بردار:
   - rustdesk-...-x86_64.exe  (۶۴ بیت)
   - rustdesk-...-x86-sciter.exe (۳۲ بیت، سازگار با ویندوز ۷)
4. اسم فایل‌ها رو به SamDesk.Customer.exe و غیره تغییر بده و بذار توی C:\SamDesk\Site\downloads

نکته: نام فایل exe و آیکن هنوز برند RustDesk دارن؛ برندینگ کامل (آیکن/لوگو) مرحله بعدی است.
نکته AGPL-3.0: چون سورس تغییر داده شده و به دیگران ارائه می‌شه، باید سورس همین نسخه در دسترس کاربران باشه (ریپوی public کافیه).
