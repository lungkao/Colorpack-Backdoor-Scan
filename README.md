<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/colorpack-logo-dark.svg">
    <img src="assets/colorpack-logo-light.svg" alt="COLORPACK CREATIONS" width="320">
  </picture>
</p>

# Colorpack Backdoor Scan V2.0.2

<a href="https://buymeacoffee.com/cheuachatchai" >![buy_me_a_coffee](https://github.com/conseilgouz/plg_system_cgwebp_j4/assets/19435246/4fda4cb5-64f1-4717-81ae-c71a0fc26c2d)</a>

**[ภาษาไทย](#ภาษาไทย) · [English](#english) · [Changelog / ประวัติการแก้ไข](#changelog--ประวัติการแก้ไข)**

**File / ไฟล์:** [`advance-scan-backdoor.php`](advance-scan-backdoor.php) · PHP 7.0+ · ไม่ต้องติดตั้ง / no installation

---

<a id="ภาษาไทย"></a>
# 🇹🇭 ภาษาไทย

เครื่องมือสแกน backdoor และจัดการไฟล์น่าสงสัยแบบ **ไฟล์เดียว** สำหรับเว็บ Joomla และ PHP ทั่วไป
อัปโหลด → ล็อกอิน → สแกน → ตรวจสอบ → ลบ/แก้ไข เหมาะกับโฮสต์ที่มีแค่ FTP หรือ File Manager (ไม่มี SSH)

## ⚠️ สำคัญ — ผลสแกนไม่ใช่การรับรองความปลอดภัย

ระบบตรวจ **pattern ที่รู้จักในไฟล์** และตรวจการตั้งค่า PHP/เซิร์ฟเวอร์เบื้องต้นเท่านั้น
ผล "ไม่พบ" **ไม่ได้แปลว่าเว็บปลอดภัย 100%** ต้องตรวจเพิ่มเองเสมอ:

| ระบบไม่ตรวจ | |
|---|---|
| ฐานข้อมูล | admin ปลอม, เนื้อหาที่ถูก inject |
| Log | access log / error log |
| Cron | งานตั้งเวลาที่ถูกฝัง |
| รูปแบบใหม่ | backdoor ที่ยังไม่มี pattern |

## วิธีใช้

1. เปิดไฟล์ แก้รหัสผ่านที่ด้านบน (**บังคับ ยาว 12 ตัวอักษรขึ้นไป และไม่ซ้ำกันในแต่ละเว็บ**):
   ```php
   $PASSWORD = 'รหัสผ่านสุ่มยาวๆ';
   ```
   ตราบใดที่ยังเป็นค่าเริ่มต้น ตัวสแกนจะไม่ทำงาน
2. อัปโหลดเข้าเว็บที่จะสแกน (สแกนโฟลเดอร์ที่ไฟล์วางอยู่ลงไปทั้งหมด วางที่ webroot = สแกนทั้งเว็บ)
3. เปิด `https://yoursite.com/advance-scan-backdoor.php` แล้วล็อกอิน
4. กด **เริ่มสแกน** ดูผล เริ่มจากระดับ **วิกฤต (CRITICAL)**
5. **ลบตัวสแกนออกจากเซิร์ฟเวอร์ทันทีเมื่อใช้เสร็จ**

> ⚠️ ห้ามทิ้งเครื่องมือนี้ไว้บนเซิร์ฟเวอร์จริง เพราะแก้และลบไฟล์ได้

### ตัวเลือก (บนสุดของไฟล์)

| ตัวเลือก | ความหมาย |
|---|---|
| `$PASSWORD` | รหัสผ่านเข้าใช้ (12 ตัวอักษรขึ้นไป) |
| `$ALLOW_IPS` | อนุญาตเฉพาะ IP ที่ระบุ เช่น `['203.0.113.5']` (ว่าง = ทุก IP) |
| `$REQUIRE_HTTPS` | ไม่รับ HTTP ธรรมดา (ค่าเริ่มต้น `true` ตั้ง `false` เฉพาะทดสอบในเครื่อง) |
| `$EXPIRES` | ปิดตัวเองหลังวันที่กำหนด เช่น `'2026-12-31 23:59'` |
| `$ENABLE_WRITE` | `false` = สแกนและดูโค้ดเท่านั้น (ไม่มีลบ/แก้ไข) |

## ความสามารถ

**ความปลอดภัยของตัวเครื่องมือ**
- ล็อกอินด้วย session (รหัสไม่อยู่ใน URL), จำกัด 5 ครั้งต่อ 15 นาทีต่อ IP, ตัวเลือก HTTPS / IP / วันหมดอายุ
- **Audit log** บันทึกทุกการล็อกอิน สแกน ดูโค้ด แก้ไข ลบ (ปุ่ม "ประวัติ" บนแถบด้านบน)
- แก้ไข/ลบได้เฉพาะไฟล์ที่ผลสแกนรายงาน และห้ามแตะตัวสแกนเอง กับ `configuration.php`
- สำรองไฟล์เป็น `.quarantine` ในโฟลเดอร์ที่เปิดผ่านเว็บไม่ได้ ถ้าสำรองไม่สำเร็จจะไม่ลบ

**การตรวจจับ**
- PHP → shell, reverse shell, dropper/uploader, eval ซ้อนหลายชั้น, callback/include ที่รับค่าจาก request
- การฝังถาวรผ่าน `.htaccess` / `.user.ini` (`auto_prepend_file`, `AddHandler`), cloaking / SEO spam, JS skimmer และ miner
- **เครื่องมือจัดการไฟล์** (Tiny File Manager, PHP File Manager ฯลฯ) ตรวจจากความสามารถ ไม่ใช่แค่ชื่อ และเตือนรหัสผ่านเริ่มต้น
- เส้นทางแบบ WordPress, ไฟล์ชื่อ hex แบบ dropper, สำเนาตัวสแกนที่ตกค้าง
- ไฟล์ใหญ่ตรวจทั้งส่วนหัวและท้าย (กันการซ่อนด้วย padding)

**ตรวจ PHP / เซิร์ฟเวอร์:** เวอร์ชัน PHP, `disable_functions`, `display_errors`, `open_basedir`, การตั้งค่า session, สิทธิ์ไฟล์, ไฟล์ backup/ความลับที่เปิดอยู่ใน webroot

**หน้าใช้งาน**
- Risk score แบบเป็นชั้น (รายการระดับกลางล้วนไม่มีวันดูเหมือนมี backdoor จริง), หนึ่งไฟล์ต่อหนึ่งแถว, ค้นหาข้ามแท็บ
- ดู/แก้โค้ดในหน้าต่าง popup พร้อม **ไฮไลต์บรรทัดที่น่าสงสัย** และปุ่มกระโดดไปบรรทัดนั้น
- **สแกนเป็นรอบสั้นๆ** (รอบละ ~12 วินาที) เว็บใหญ่แค่ไหนก็ไม่เจอ `504 Gateway Time-out`
- ผลสแกนถูกเก็บไว้ (`?view=last`) กด Back หรือรีเฟรชแล้วไม่หาย และสแกนใหม่เองเมื่อมีไฟล์เปลี่ยน

## ระดับความรุนแรง

- **CRITICAL (วิกฤต)** เกือบแน่ว่าเป็น backdoor เช่น `eval` ของข้อมูลที่ decode, `eval/system` รับค่า request, ตัวโหลด `zip://`, reverse shell, `auto_prepend_file`, hash ของ webshell ที่รู้จัก, PHP ในรูปภาพ, เครื่องมือจัดการไฟล์
- **HIGH (สูง)** สัญญาณแรง ดูโค้ดก่อนลบ เช่น obfuscation, signature webshell, PHP ในโฟลเดอร์ upload, นามสกุลซ้อน, cloaking, dropper
- **MEDIUM (กลาง)** น่าดู เช่น `hex2bin`, ลิงก์ซ่อน, ไฟล์ entropy สูง

มี false positive ได้ในปลั๊กอิน/ไลบรารีที่ถูกต้อง ให้กด **ดู code** (บรรทัดน่าสงสัยจะถูกไฮไลต์) ก่อนตัดสินใจลบ

## เจอ backdoor แล้วทำอย่างไร

1. ปิดเว็บ (offline) และสำรองทุกอย่าง (เก็บไฟล์ติดมัลแวร์ไว้เป็นหลักฐาน)
2. ลบไฟล์ CRITICAL / HIGH (ระบบเก็บสำเนา quarantine ให้ก่อน)
3. เปลี่ยน **รหัสผ่านทุกตัว** — ฐานข้อมูล, FTP, แผงควบคุมโฮสต์, admin ของ CMS
4. ตรวจฐานข้อมูลหา admin แปลกปลอมและเนื้อหาที่ถูก inject
5. ดู access log หาช่องทางที่เข้ามา อัปเดต CMS, ส่วนเสริม และ PHP
6. สแกนซ้ำก่อนเปิดเว็บ แล้ว **ลบตัวสแกนออก**

---

<a id="english"></a>
# 🇬🇧 English

A **single-file** PHP backdoor scanner and incident-response console for Joomla and general PHP websites.
Upload → sign in → scan → review → delete/edit. Built for shared hosting with only FTP / a file manager (no SSH).

## ⚠️ Important — a clean result is not a guarantee

The tool detects **known patterns in files** and audits basic PHP/server settings only.
A "clean" result does **not** prove the site is free of malware. Always also check:

| Not covered | |
|---|---|
| Database | rogue admins, injected content |
| Logs | access / error logs |
| Cron | planted scheduled tasks |
| Novel malware | techniques without a known pattern |

## Quick start

1. Edit the password at the top of the file (**required, 12+ characters, unique per site**):
   ```php
   $PASSWORD = 'your-long-random-password';
   ```
   The scanner refuses to run while it is still the placeholder.
2. Upload it into the site you want to scan (it scans the folder it sits in, recursively).
3. Open `https://yoursite.com/advance-scan-backdoor.php` and sign in.
4. Press **เริ่มสแกน** (Start scan), review the findings, begin with **CRITICAL**.
5. **Delete the scanner from the server as soon as you are done.**

> ⚠️ Never leave this tool on a production server. It can edit and delete files.

### Options (top of the file)

| Option | Meaning |
|---|---|
| `$PASSWORD` | Login password (12+ chars) |
| `$ALLOW_IPS` | Only these IPs may open the tool, e.g. `['203.0.113.5']` (empty = any) |
| `$REQUIRE_HTTPS` | Refuse plain HTTP (default `true`; set `false` only for local testing) |
| `$EXPIRES` | Self-disable after a date, e.g. `'2026-12-31 23:59'` |
| `$ENABLE_WRITE` | `false` = scan and view code only (no delete / edit) |

## Features

**Security of the tool itself**
- Session login (no password in the URL), 5 attempts / 15 min / IP, HTTPS / IP / expiry options
- **Audit log** of every login, scan, view, edit and delete (the "ประวัติ" button in the top bar)
- Edit / delete only for files reported by the last scan; the scanner itself and `configuration.php` are protected
- Backups are stored as `.quarantine` files in a folder that cannot be opened over HTTP; no backup → no delete

**Detection**
- PHP → shell, reverse shells, droppers/uploaders, nested `eval` decoders, callbacks/`include` fed with request data
- Persistence via `.htaccess` / `.user.ini` (`auto_prepend_file`, `AddHandler`), cloaking / SEO spam, JS skimmers & miners
- **Web file managers** (Tiny File Manager, PHP File Manager, …) detected by capability, not only by name; default credentials flagged
- WordPress paths, random hex-named droppers, leftover scanner copies
- Large files are scanned head + tail (padding trick)

**PHP / server audit:** PHP version, `disable_functions`, `display_errors`, `open_basedir`, session flags, file permissions, exposed backup / secret files

**Interface**
- Tiered risk score (medium-only findings can never look like a confirmed backdoor), one row per file, global search
- Code viewer / editor popup with **suspicious lines highlighted** and jump-to-line
- **Scans in short rounds** (~12 s each), so large sites never hit `504 Gateway Time-out`
- Results are stored (`?view=last`): Back / refresh keep them, and the tool re-scans on its own when files change

## Severity levels

- **CRITICAL** — near-certain backdoor: `eval` of decoded data, `eval/system` on request input, `zip://` loaders, reverse shells, `auto_prepend_file`, known webshell hashes, PHP inside images, web file managers
- **HIGH** — strong indicators, check the code before deleting: obfuscation, webshell signatures, PHP in upload folders, double extensions, cloaking, droppers
- **MEDIUM** — worth a look: `hex2bin`, hidden links, high-entropy files

False positives are possible in legitimate plugins/libraries. Use **ดู code** (suspicious lines are highlighted) before deleting.

## After finding a backdoor

1. Take the site **offline**; back up everything (keep the infected files as evidence)
2. Delete CRITICAL / HIGH files (the tool stores a quarantined copy first)
3. Reset **all** passwords — database, FTP, hosting panel, CMS admins
4. Check the database for rogue admin users and injected content
5. Review access logs for the entry point; update the CMS, extensions and PHP
6. Re-scan before going back online, then **remove the scanner**

---

<a id="changelog--ประวัติการแก้ไข"></a>
# Changelog / ประวัติการแก้ไข

Full details / รายละเอียดทั้งหมด: [CHANGELOG.md](CHANGELOG.md)

| Version | Date | TH | EN |
|---|---|---|---|
| **2.0.2** | 2026-10-25 | แก้ `504 Gateway Time-out` ถาวร: สแกนเป็นรอบสั้นๆ ที่เบราว์เซอร์เรียกต่อกันเอง | Permanent fix for `504 Gateway Time-out`: the scan runs in short rounds driven by the browser |
| 2.0.1 | 2026-10-23 | ลด 504 (จับเวลานับ cache, ล้าง cache เป็นรอบ), ฝังโลโก้ Colorpack, ปุ่ม Buy Me a Coffee | 504 mitigation (time-boxed cache stats, resumable cache clearing), Colorpack logo, Buy Me a Coffee button |
| 2.0.0 | 2026-10-23 | รุ่นใหญ่: ระบบความปลอดภัยใหม่, กฎตรวจจับใหม่, ตรวจ PHP/เซิร์ฟเวอร์, หน้าตาใหม่ | Major release: new security model, new detection rules, PHP/server audit, new interface |
| 1.0.0 | 2026-06-11 | รุ่นแรก `scan-backdoor.php` (อ่านอย่างเดียว) | First release `scan-backdoor.php` (read-only) |

---

## Credits

© 2026 บริษัท คัลเลอร์แพค ครีเอชั่น จำกัด (Colorpack Creation Co., Ltd.) · [colorpack.co.th](https://colorpack.co.th/)

## สนับสนุนผู้พัฒนา / Support the author

ถ้าเครื่องมือนี้ช่วยคุณได้ เลี้ยงกาแฟผู้พัฒนาได้ที่นี่ · If this tool helped you, you can buy the author a coffee:

<a href="https://buymeacoffee.com/cheuachatchai" >![buy_me_a_coffee](https://github.com/conseilgouz/plg_system_cgwebp_j4/assets/19435246/4fda4cb5-64f1-4717-81ae-c71a0fc26c2d)</a>
