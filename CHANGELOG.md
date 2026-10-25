# Changelog / ประวัติการแก้ไข

Colorpack Backdoor Scan — [README](README.md)

Format: each version has a Thai (TH) and an English (EN) list.
รูปแบบ: แต่ละรุ่นมีรายการภาษาไทย (TH) และภาษาอังกฤษ (EN)

---

## [2.0.2] — 2026-10-25

### TH
**แก้ไข**
- แก้ `504 Gateway Time-out` (nginx) แบบถาวร: เดิมสแกนทั้งเว็บใน **คำขอเดียว** ที่เปิดค้างไว้ ซึ่งตัวกลางของโฮสต์ (nginx, Apache ด้านหลัง, ตัวกันของโฮสต์) อาจตัดเมื่อเกินเวลา ตอนนี้เบราว์เซอร์เรียกเซิร์ฟเวอร์ต่อกันทีละรอบ รอบละประมาณ 12 วินาที (`scan_start` / `scan_step`) จึงไม่มีคำขอไหนยาวพอจะถูกตัด

**เปลี่ยนแปลง**
- สแกนสองขั้น: สำรวจโฟลเดอร์เก็บรายชื่อไฟล์ → ตรวจโค้ดตามรายชื่อ ทำต่อได้ ไม่ตรวจซ้ำรอบเดิมถ้าต้องลองใหม่
- แสดงความคืบหน้าจริง ("ตรวจแล้ว X / Y ไฟล์ · พบสิ่งน่าสงสัย Z จุด") ลองเรียกใหม่เองได้ 5 ครั้งเมื่อเน็ตหลุด
- แยกโค้ดตรวจไฟล์เดียวเป็นฟังก์ชันกลาง ใช้ร่วมกันทั้ง CLI และการสแกนบนเว็บ (ผลตรงกับเดิมทุกรายการ)
- เมื่อพบไฟล์ใหม่/เปลี่ยนหลังสแกน ระบบพาไปสแกนใหม่แบบแบ่งรอบ และไม่นับไฟล์ใน `cache/`, `tmp/`, `logs/` ที่เปลี่ยนตลอดเวลา (กันสแกนวนไม่จบ)

### EN
**Fixed**
- Permanent fix for `504 Gateway Time-out` (nginx): the whole site used to be scanned in **one long request** that a host's proxy layer (nginx, Apache behind it, host firewalls) could cut. The browser now drives the scan in short rounds of about 12 seconds (`scan_start` / `scan_step`), so no single request is long enough to be cut.

**Changed**
- Two-phase scan: walk the folders and write a file list → inspect the files from that list. Resumable; a retried round is never processed twice.
- Real progress ("scanned X / Y files · Z suspicious findings"), automatic retry (5 times) when the connection drops.
- The single-file inspection code is now one shared function used by both the CLI and the web scan (results are identical to before).
- When files were added/changed after the last scan, the tool re-scans in rounds; files in the volatile `cache/`, `tmp/`, `logs/` folders are ignored so it cannot loop forever.

---

## [2.0.1] — 2026-10-23

### TH
**แก้ไข**
- ลดปัญหา `504 Gateway Time-out`: จับเวลานับไฟล์ cache/tmp บนหน้าแรก (2.5 วินาที), เลิกนับไฟล์ล่วงหน้าแบบเงียบๆ, ส่งสัญญาณระหว่างสแกนทุก 3 วินาที, สแกนต่อให้จบแม้ proxy ตัดการเชื่อมต่อ (เปิด `?view=last`)
- ล้าง cache เป็นรอบละไม่เกิน 20 วินาที และตรวจ symlink กันลบนอก root
- กฎ "backtick shell" ไม่ติด SQL ที่ใช้ backtick ครอบชื่อตาราง

**เพิ่ม**
- ฝังโลโก้ COLORPACK CREATIONS (inline SVG) ในหน้าล็อกอิน แถบบน ท้ายหน้า และหน้าประวัติ
- เครื่องมือจัดการไฟล์ (Tiny File Manager ฯลฯ) ถูกจัดเป็นระดับวิกฤต, ตรวจ hash รหัสผ่านเริ่มต้น, ช่องค้นหาข้ามทุกแท็บ
- ไฮไลต์บรรทัดที่น่าสงสัยในหน้าดู/แก้โค้ด, หนึ่งไฟล์ต่อหนึ่งแถว, Risk score แบบเป็นชั้น
- ปุ่ม Buy Me a Coffee และ README สองภาษา

### EN
**Fixed**
- 504 mitigation: time-boxed cache/tmp statistics on the start page (2.5 s), removed the silent pre-count pass, keep-alive output every 3 s while scanning, scan finishes even if a proxy drops the connection (open `?view=last`)
- Cache clearing runs in rounds of at most 20 s and checks symlinks so nothing outside the root is deleted
- The "backtick shell" rule no longer matches SQL that quotes table names with backticks

**Added**
- Embedded COLORPACK CREATIONS logo (inline SVG) on the sign-in page, top bar, footer and audit page
- Web file managers (Tiny File Manager, …) rated CRITICAL, default-password hash detection, global search across tabs
- Suspicious-line highlighting in the code viewer/editor, one row per file, tiered risk score
- Buy Me a Coffee button and a bilingual README

---

## [2.0.0] — 2026-10-23

### TH
**ความปลอดภัยของเครื่องมือ**
- ล็อกอินด้วย session (ไม่มีรหัสใน URL), จำกัด 5 ครั้ง/15 นาที/IP, ตัวเลือก HTTPS / IP allow-list / วันหมดอายุ
- Audit log ทุกการกระทำ, แก้ไข/ลบเฉพาะไฟล์ที่สแกนเจอ, สำรองเป็น `.quarantine` ในโฟลเดอร์ที่เปิดผ่านเว็บไม่ได้, CSRF key ต่อ session, แก้ XSS, security headers
- รหัสผ่านเริ่มต้นเป็น placeholder: ถ้ายังไม่ตั้งรหัสเอง ตัวสแกนไม่ทำงาน

**การตรวจจับ**
- PHP → shell, reverse shell, เลี่ยง `disable_functions`, dropper/uploader, eval ซ้อนหลายชั้น, callback/include ที่รับค่าจาก request
- ฝังถาวรผ่าน `.htaccess` / `.user.ini`, cloaking / SEO spam, JS skimmer/miner, เครื่องมือจัดการไฟล์, เส้นทาง WordPress, สำเนาตัวสแกนที่ตกค้าง
- ไฟล์ใหญ่ตรวจส่วนหัวและท้าย, รายงานเมื่อ regex ชนข้อจำกัด

**ตรวจ PHP / เซิร์ฟเวอร์** — เวอร์ชัน PHP, `disable_functions`, `display_errors`, `open_basedir`, session, สิทธิ์ไฟล์, ไฟล์ backup/ความลับใน webroot

**หน้าตา** — ธีมสว่าง, Risk score, ผลสแกนเก็บไว้ (`?view=last`) และสแกนใหม่เองเมื่อไฟล์เปลี่ยน, popup ดู/แก้โค้ด

**เปลี่ยนแปลง** — เหลือไฟล์เดียว `advance-scan-backdoor.php` เอา `scan-backdoor.php` (V1.0) ออกจาก repo

### EN
**Security of the tool**
- Session login (no password in the URL), 5 attempts / 15 min / IP, HTTPS / IP allow-list / expiry options
- Audit log of every action, edit/delete only for scanned files, `.quarantine` backups in a folder that cannot be opened over HTTP, per-session CSRF key, XSS fixes, security headers
- The default password is a placeholder: the scanner will not run until you set your own

**Detection**
- PHP → shell, reverse shells, `disable_functions` bypass, droppers/uploaders, nested `eval` decoders, callbacks/`include` fed with request data
- `.htaccess` / `.user.ini` persistence, cloaking / SEO spam, JS skimmers/miners, web file managers, WordPress paths, leftover scanner copies
- Large files scanned head + tail, regex-limit failures reported

**PHP / server audit** — PHP version, `disable_functions`, `display_errors`, `open_basedir`, session flags, file permissions, exposed backup / secret files

**Interface** — light theme, risk score, stored results (`?view=last`) with automatic re-scan when files change, code viewer/editor popup

**Changed** — now a single file, `advance-scan-backdoor.php`; the legacy `scan-backdoor.php` (V1.0) was removed from the repository

---

## [1.0.0] — 2026-06-11

### TH
- รุ่นแรก `scan-backdoor.php`: สแกนอ่านอย่างเดียวด้วย pattern ของ backdoor ที่พบในเคสจริง (`eval(php://input)`, ตัวโหลด `zip://`, Tiny File Manager ฯลฯ)

### EN
- First release, `scan-backdoor.php`: read-only scanner with patterns from real incidents (`eval(php://input)`, `zip://` loaders, Tiny File Manager, …)
