# Colorpack Backdoor Scan V1.0

**[EN]** Single-file PHP backdoor scanner for Joomla and general PHP websites.  
No dependencies, no installation. Upload → open URL → scan → delete.

**[TH]** เครื่องมือสแกนหา backdoor แบบไฟล์เดียว สำหรับเว็บ Joomla และ PHP ทั่วไป  
ไม่ต้องติดตั้ง — upload แล้วเปิดผ่าน browser ได้เลย

---

## ⚠️ IMPORTANT — ระบบอาจตรวจสอบได้ไม่ครบทั้งหมด

> **[EN]** This scanner detects **known patterns in PHP files only**.  
> A "clean" result does **not** guarantee your site is free of malware.  
> Always combine with manual review, log analysis, and database inspection.

> **[TH]** ระบบตรวจเฉพาะ **pattern ที่รู้จักในไฟล์ PHP** เท่านั้น  
> ผลสแกน "ไม่พบ" **ไม่ได้หมายความ** ว่าเว็บปลอดภัย 100%  
> ต้องตรวจสอบเพิ่มเติมด้วยตนเองเสมอ

**สิ่งที่ระบบไม่ตรวจ / NOT covered by this scanner:**

| ไทย | English |
|-----|---------|
| ฐานข้อมูล (admin ปลอม, content ถูก inject) | Database — rogue admins, injected content |
| Access log / error log | Server access & error logs |
| Cron jobs / scheduled tasks | Cron jobs & scheduled tasks |
| Config files (`.htaccess`, `nginx.conf`) | Server configuration files |
| Backdoor รูปแบบใหม่ที่ยังไม่รู้จัก | Novel / unknown obfuscation techniques |
| ปัญหา file permissions | Insecure file & directory permissions |
| Webshell ในไฟล์ที่ไม่ใช่ PHP | Webshells embedded in non-PHP files |

---

สร้างจากเคส nccthailand.com (โดนแฮก เม.ย. 2025: `eval(php://input)` + Tiny File
Manager webshell 10 จุดผ่าน `zip://` loader). เอาไปสแกนเว็บอื่น โดยเฉพาะ **shared
host** ที่มีแค่ FTP/web panel

มี 2 เวอร์ชัน เนื้อหา detection เหมือนกัน:

| ไฟล์ | ใช้เมื่อ | วิธีรัน |
|------|---------|---------|
| `scan-backdoor.php` | sharehost / FTP เท่านั้น (ไม่มี SSH) | upload แล้วเปิดผ่าน browser |
| `scan-backdoor.sh` | มี SSH | `bash scan-backdoor.sh /path` |

ทั้งคู่ **read-only** — แค่ walk ไฟล์ + match pattern ไม่ eval ไม่แก้ไฟล์เป้าหมาย

---

## วิธีใช้ — PHP (sharehost)

1. เปิด `scan-backdoor.php` แก้บรรทัด:
   ```php
   $PASSWORD = 'CHANGE_ME_to_a_long_random_string';
   ```
   เป็น password สุ่มยาวๆ (กันคนอื่นเปิด scanner)
2. upload ไป webroot ของเว็บที่จะสแกน (ผ่าน FTP / File Manager)
3. เปิด browser:
   ```
   https://yoursite.com/scan-backdoor.php?key=PASSWORD_ที่ตั้ง
   ```
4. อ่านรายงาน (ตาราง CRITICAL / HIGH / MEDIUM)
5. **ลบ `scan-backdoor.php` ออกจาก server ทันทีหลังใช้เสร็จ**

scanner สแกนโฟลเดอร์ที่ตัวมันอยู่ลงไปทั้งหมด → วางที่ webroot = สแกนทั้งเว็บ

## วิธีใช้ — bash (มี SSH)

```bash
bash scan-backdoor.sh /home/user/public_html
# หรือ cd เข้า webroot แล้ว
bash scan-backdoor.sh
```

exit code: `1` = เจอ CRITICAL, `0` = ไม่เจอ (ใช้ใน cron/automation ได้)

---

## ตรวจอะไรบ้าง

**CRITICAL** (เกือบแน่ว่า backdoor — ลบได้หลังยืนยัน path):
- `include/require` จาก `zip://` `phar://` `compress.zlib://` (loader ซ่อน payload ใน archive)
- `eval()`/`assert()` บน `php://input`
- `eval()` ของข้อมูลที่ decode (`base64_decode`, `gzinflate`, `str_rot13`, ...)
- `eval/system/shell_exec/...` รับ `$_GET/$_POST/$_REQUEST/$_COOKIE` ตรงๆ
- goto flow-flattening (≥15 goto = obfuscation แบบที่เจอใน `api.php`)
- dynamic call `$_GET['x']()`
- `strrev('46esab')` / `strrev('etalfnizg')` — สร้าง function name จากสตริงกลับหัว
- `openssl_decrypt(...)` ที่รับ key จาก `$_REQUEST` (AES-encrypted shell)
- Unicode/binary variable names — ชื่อตัวแปรเป็น non-ASCII (≥50 U+FFFD, `$\xNN...`, หรือ >45% UTF-8 3-byte sequences)
- MD5 ตรงกับ backdoor ที่เจอในเคส ncc + babimild (exact match)
- ไฟล์ `index.zip` (Tiny File Manager payload)

**CRITICAL** (เพิ่มเติม):
- PHP `<?php` tag พบใน `.jpg/.gif/.png/.svg` (polyglot shell — upload bypass)

**HIGH** (สัญญาณแรง — ดู context ก่อนลบ):
- `preg_replace` modifier `/e`, `create_function`
- hex-string ยาว, base64 ป้อนเข้า eval
- signature webshell ที่รู้จัก (c99, r57, WSO, b374k, FilesMan, Tiny File Manager ฯลฯ)
- `@session_start()` + `@set_time_limit(0)` ในไฟล์เดียวกัน (file-manager webshell)
- `data:image/...;base64,PAYLOAD` + `preg_match` (payload ซ่อนใน data URI)
- ไฟล์ `adman.NNN.txt` (AdmaNi toolkit hit-counter — บ่งบอกว่า shell ยังอยู่)
- ไฟล์ `.php` อยู่ใน `images/ media/ cache/ tmp/ files/ logs/ assets/` (ยกเว้น Joomla stub)
- `$f = 'system'` — ตัวแปรถูก assign ชื่อ shell function (indirect execution)
- `$f = "\x73\x79\x73..."` — hex string สั้น (4+ bytes) assign ให้ตัวแปร (obfuscated name)
- `chmod(0777)` + `file_put_contents/move_uploaded_file` (post-drop permission escalation)
- double extension `.php.jpg` / `.php.gif` — เลี่ยง upload filter

**MEDIUM** (น่าดู):
- function name ประกอบจาก `chr()`, dropper (fetch remote + write), `error_reporting(0)` ติด eval/decoder
- Shannon entropy >7.2 bits/byte — ไฟล์ที่มี encrypted/packed payload ซ่อนอยู่

---

## ข้อจำกัด — สำคัญ

scanner ดู **เฉพาะไฟล์** ยืนยันสะอาด 100% ไม่ได้ ต้องเช็คเพิ่ม:

- **Database** — Joomla `#__users` หา Super User แปลกปลอม, `#__session`
- **Access log** — POST ไป path น่าสงสัย, IP ผู้โจมตี
- **Cron jobs** — อาจมี backdoor เรียกตามเวลา
- ระดับ **server** นอก webroot

**False positive:** plugin/library ปกติบางตัวใช้ `create_function`, hex string, หรือ
`preg_replace` ได้ → HIGH/MEDIUM ต้องเปิดดูโค้ดก่อนตัดสินใจลบ ส่วน CRITICAL +
MD5-match = มั่นใจได้

## เจอแล้วทำไง / What to do after finding backdoors

**[TH]**
ดู `SECURITY-INCIDENT-REPORT.md` — มีคำสั่งลบ + ขั้นตอนหลังลบ
(เปลี่ยน password ทุกตัว, ดู DB, ดู log, หาช่องที่เข้ามา) ใช้เป็น template ได้ทุกเว็บ

**[EN] Immediate steps:**
1. Take the site **offline** immediately
2. Backup everything (including infected files as evidence)
3. Delete CRITICAL/HIGH files
4. Reset **all passwords** — database, FTP, cPanel, CMS admin accounts
5. Scan the database for injected content and rogue admin users
6. Review access logs to identify the attack vector
7. Update Joomla/CMS, all extensions, and PHP
8. Re-scan after cleanup before going back online

---

## Usage — วิธีใช้งาน (EN)

### Requirements
- PHP **7.0+**
- Ability to upload a file to the server (FTP, File Manager, etc.)

### Steps
1. Open `scan-backdoor.php` and change the password:
   ```php
   $PASSWORD = 'your-strong-unique-password';
   ```
2. Upload to the website root (or directory you want to scan)
3. Open in browser:
   ```
   https://yoursite.com/scan-backdoor.php?key=your-strong-unique-password
   ```
4. Wait for the scan to complete (10–120 seconds)
5. Review results — act on **CRITICAL** and **HIGH** findings immediately
6. **Delete the scanner file from the server right after use**

> Scanner runs from the directory it is placed in — upload to webroot to scan the entire site.

---

## Credits

จัดทำโดย ทีมงาน บริษัท คัลเลอร์แพค ครีเอชั่น จำกัด · [colorpack.co.th](https://colorpack.co.th/)
