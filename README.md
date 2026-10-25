<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/colorpack-logo-dark.svg">
    <img src="assets/colorpack-logo-light.svg" alt="COLORPACK CREATIONS" width="320">
  </picture>
</p>

# Colorpack Backdoor Scan V2.0.1

**[EN]** Single-file PHP backdoor scanner + incident-response console for Joomla and general PHP websites.
No dependencies, no installation: upload → sign in → scan → review → clean up.

**[TH]** เครื่องมือสแกน backdoor และจัดการไฟล์น่าสงสัยแบบไฟล์เดียว สำหรับเว็บ Joomla และ PHP ทั่วไป
ไม่ต้องติดตั้ง — อัปโหลด → ล็อกอิน → สแกน → ตรวจสอบ → ลบ/แก้ไข

**File / ไฟล์:** [`advance-scan-backdoor.php`](advance-scan-backdoor.php) (V2.0.1, requires PHP 7.0+)

---

## ⚠️ IMPORTANT — ผลสแกนไม่ใช่การรับรองความปลอดภัย

> **[EN]** This tool detects **known patterns in files** and audits basic PHP/server settings.
> A "clean" result does **not** prove the site is free of malware. Always combine it with
> database inspection, log analysis and manual review.
>
> **[TH]** ระบบตรวจเฉพาะ **pattern ที่รู้จักในไฟล์** และตรวจการตั้งค่า PHP/เซิร์ฟเวอร์เบื้องต้น
> ผล "ไม่พบ" ไม่ได้แปลว่าเว็บปลอดภัย 100% ต้องตรวจฐานข้อมูล, log และตรวจด้วยตนเองเพิ่มเสมอ

| ไทย | English |
|-----|---------|
| ฐานข้อมูล (admin ปลอม, content ถูก inject) | Database — rogue admins, injected content |
| Access log / error log | Server access & error logs |
| Cron jobs / scheduled tasks | Cron jobs & scheduled tasks |
| Backdoor รูปแบบใหม่ที่ยังไม่รู้จัก | Novel / unknown obfuscation techniques |

---

## วิธีใช้ / Quick start

1. Edit the password at the top of the file (**required, 12+ characters, unique per site**):
   ```php
   $PASSWORD = 'your-long-random-password';
   ```
   The scanner refuses to run while it is still the placeholder.
2. Upload the file into the website you want to scan (the scan covers the folder it sits in).
3. Open `https://yoursite.com/advance-scan-backdoor.php` and sign in.
4. Press **เริ่มสแกน**, review the findings, act on **CRITICAL** first.
5. **Delete the scanner from the server when you are done.**

> Never leave this tool on a production server. It can edit and delete files.

### Options (top of the file)

| Option | Meaning |
|--------|---------|
| `$PASSWORD` | Login password (12+ chars) |
| `$ALLOW_IPS` | Only these IPs may open the tool, e.g. `['203.0.113.5']` (empty = any) |
| `$REQUIRE_HTTPS` | Refuse plain HTTP (default `true`; set `false` only for local testing) |
| `$EXPIRES` | Self-disable after a date, e.g. `'2026-12-31 23:59'` |
| `$ENABLE_WRITE` | `false` = scan and view code only (no delete / edit) |

---

## What's new in 2.0.1

- **Fixes `504 Gateway Time-out` (nginx) on large sites:** cache/tmp statistics are time-boxed, the silent pre-count pass is gone,
  the scan sends keep-alive output, cache clearing runs in resumable rounds, and a scan that a proxy cuts off still finishes and
  is cached — open `?view=last` to see the result. On very large sites also raise `fastcgi_read_timeout` / `request_terminate_timeout`.

## What's new in 2.0

**Security**
- Session login (no password in the URL), rate limit 5 attempts / 15 min / IP, HTTPS / IP / expiry options
- **Audit log** of every login, scan, view, edit and delete (viewable from the toolbar)
- Edit / delete only for files reported by the last scan; scanner itself and `configuration.php` are protected
- Backups are stored as `.quarantine` files in a folder that cannot be opened over HTTP; no backup → no delete
- CSRF key per session, XSS fixes, security headers

**Detection**
- PHP → shell: shell-exec with request data, backticks, reverse shells, `LD_PRELOAD` / `disable_functions` bypass
- Droppers and uploaders, nested decoders, callback / `include` fed with request data
- `.htaccess` / `.user.ini` persistence (`auto_prepend_file`, `AddHandler`), cloaking / SEO spam, JS skimmers & miners
- **Web file managers** (Tiny File Manager, PHP File Manager, …) detected by capability, not only by name; default credentials flagged
- WordPress paths (PHP in uploads, mu-plugins, look-alikes), random hex-named droppers, leftover scanner copies
- Large files scanned head + tail (padding trick), regex-limit failures reported

**Server audit** — PHP version, `disable_functions`, `display_errors`, `open_basedir`, session flags, file permissions, exposed backup / secret files

**Interface**
- Light theme, risk score (tiered: medium-only findings can never look like a confirmed backdoor)
- One row per file with all matching reasons, global search across tabs
- Code viewer / editor popup with **suspicious lines highlighted** and jump-to-line
- Results survive Back / refresh; automatic re-scan when files were added or changed

---

## ตรวจอะไรบ้าง / What it detects (summary)

**CRITICAL** — near-certain backdoor: `eval` of decoded data, `eval/system` on request input, `zip://` / `phar://` loaders,
reverse shells, `auto_prepend_file`, known webshell hashes, PHP inside images, web file managers with default credentials, …

**HIGH** — strong indicators, verify before deleting: obfuscation (`create_function`, hex runs, `preg_replace /e`),
known webshell signatures, PHP in upload directories, double extensions, cloaking, droppers, …

**MEDIUM** — worth a look: `chr()`-built names, `hex2bin`, hidden-link blocks, high-entropy files, hex-named PHP files, …

**False positives:** legitimate plugins/libraries may use some of these functions. HIGH / MEDIUM need a look at the code
(use **ดู code** — suspicious lines are highlighted) before deleting.

---

## เจอแล้วทำไง / What to do after finding a backdoor

1. Take the site **offline**; back up everything (keep infected files as evidence)
2. Delete CRITICAL / HIGH files (the tool stores a quarantined copy first)
3. Reset **all** passwords — database, FTP, hosting panel, CMS admins
4. Check the database for rogue admin users and injected content
5. Review access logs to find the entry point; update CMS, extensions and PHP
6. Re-scan before going back online, then **remove the scanner**

---

## Credits

© 2026 บริษัท คัลเลอร์แพค ครีเอชั่น จำกัด (Colorpack Creation Co., Ltd.) · [colorpack.co.th](https://colorpack.co.th/)
