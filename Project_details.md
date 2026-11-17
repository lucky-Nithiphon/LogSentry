LogSentry — Project Specification & Technical Blueprint
วัตถุประสงค์ของเอกสารนี้: ใช้เป็น Master Blueprint ประจำโปรเจกต์ LogSentry สำหรับบันทึกสถาปัตยกรรม ความคืบหน้า แผนการพัฒนา (Roadmap) และใช้ป้อนเป็นบริบท (Context) ให้กับ AI Assistant ในแชตอื่นๆ เพื่อสานต่อการพัฒนาได้อย่างต่อเนื่องและตรงเป้าหมาย



1. ภาพรวมโปรเจกต์และบริบทในระบบนิเวศ (Ecosystem Context)
LogSentry เป็นเครื่องมือวิเคราะห์ความปลอดภัยจากไฟล์ Log และสืบสวนร่องรอยการโจมตีทางไซเบอร์ (Out-of-band Log Scanner, Threat Hunting & Incident Forensics Engine / Mini-SIEM) พัฒนาด้วยภาษา Java

โปรเจกต์นี้เป็น ชิ้นส่วนที่ 1 จาก 3 โปรเจกต์ ในสถาปัตยกรรมป้องกันเชิงลึก (Defense-in-Depth) ที่ออกแบบมาเพื่อจำลองระบบความปลอดภัยบน Cloud Infrastructure สำหรับใช้เป็นผลงานในพอร์ตโฟลิโอสมัครงานสาย Cybersecurity และ Cloud Engineer:

LogSentry (โปรเจกต์นี้ — Out-of-band Analyzer): คอยอ่านและสแกนไฟล์ Log จากเซิร์ฟเวอร์เพื่อตรวจจับภัยคุกคามเชิงลึก วิเคราะห์พฤติกรรมย้อนหลัง แกะรอย IP ผู้โจมตี และออกรายงาน/แจ้งเตือน (เน้นความละเอียดและแม่นยำในการวิเคราะห์ โดยไม่รบกวนความเร็วของเว็บหลัก)

EdgeGuard WAF (โปรเจกต์ที่ 2 — Inline Reverse Proxy): ตัวคั่นกลางหน้าสุด (พัฒนาด้วย Go) กรอง HTTP Request แบบ Real-time ด้วย Latency ต่ำ เพื่อบล็อกทราฟฟิกขยะและการโจมตีพื้นฐานตั้งแต่หน้าประตู

AppShield RASP (โปรเจกต์ที่ 3 — Backend Security Middleware): ไลบรารีฝังร่วมกับโค้ด Backend (Python/Java) เพื่อตรวจจับช่องโหว่ระดับ Application Logic และ Context ภายในแอปพลิเคชัน


การไหลของข้อมูลเมื่อทั้ง 3 ระบบเชื่อมต่อกัน (Target Architecture)
Plaintext
[ Attacker / User ]
        │
        ▼
[ 2. EdgeGuard WAF ] ──( บล็อกทราฟฟิกอันตรายพื้นฐานหน้าประตู + เขียน WAF Log )
        │
        ▼
[ Backend App + 3. AppShield RASP ] ──( ตรวจบริบทเชิงลึก + เขียน App/Access Log )
        │
        ▼ (Shared Volume / Log Files)
[ 1. LogSentry Engine ] ──( สแกน Log, จับพฤติกรรม, แกะรอย IP & ยิง Alert เข้า Discord )




2. ปรัชญาการออกแบบ (Architectural Shift & Trade-offs)
เหตุผลที่แยกบทบาทเป็น Out-of-band Scanner: การตรวจจับที่อ่านจากไฟล์ Log เป็นการทำงานแบบ Asynchronous (ตามหลังทราฟฟิกจริง) จึงไม่เหมาะกับการนำไปใช้เป็นตัวบล็อกแบบ Inline เพราะอาจเกิด Latency หรือ Log Lag ได้ การปรับ LogSentry มาเป็น เครื่องมือสแกน วิเคราะห์เชิงลึก และแกะรอย (Forensics) ช่วยปลดล็อกข้อจำกัดเรื่องความเร็วระดับมิลลิวินาที ทำให้สามารถรันอัลกอริทึมที่ซับซ้อน (เช่น Regex หลายชั้น, Shannon Entropy, การเรียงไทม์ไลน์ย้อนหลัง และการดึงข้อมูล Threat Intel ภายนอก) ได้อย่างเต็มประสิทธิภาพโดยไม่ทำให้เว็บเซิร์ฟเวอร์หลักช้าลง

สภาพแวดล้อมการพัฒนา (Development Environment):

ภาษาหลัก: Java (Standard Library + java.util.regex, java.net.http.HttpClient, Java NIO)

Mock Environment: Python (server.py) สำหรับจำลอง Web Server และสร้างไฟล์ access.log

IDE & Deployment: พัฒนาบน VS Code / Antigravity IDE และเตรียมแพ็กขึ้น Container ด้วย Docker (Dockerfile / docker-compose.yml)



3. สถานะปัจจุบันของโค้ด (Current Baseline — v0.4.0)
ระบบพื้นฐานที่พัฒนาเสร็จและทดสอบแล้ว ประกอบด้วยไฟล์หลักดังนี้:

server.py (Mock Web Server): เซิร์ฟเวอร์จำลองด้วย Python ที่รับ HTTP Request และเขียนบันทึกลงไฟล์ access.log แบบ Real-time

Main.java & File Tailer: ตัวควบคุมหลักที่คอยเฝ้าอ่านบรรทัดใหม่จากไฟล์ access.log อย่างต่อเนื่อง (Live Tailing Pattern)

LogEntry.java: โมเดลเก็บข้อมูลที่ Parse ออกมาจากแต่ละบรรทัดของ Log (IP, Timestamp, HTTP Method, Request Path/Query, Status Code)

LogSanitizer.java: ระบบ Normalize ข้อมูล ทำการถอดรหัส URL Encoding ซ้อนหลายชั้น (Multi-layer URL Decoding) ก่อนส่งไปตรวจ เพื่อป้องกันเทคนิคการแปลงอักขระหลบเลี่ยง (Obfuscation Bypass)

ThreatDetector.java (Regex Engine): อัปเกรดจากการใช้ .contains() มาเป็น Pre-compiled java.util.regex.Pattern (static final + CASE_INSENSITIVE) ครอบคลุม 4 หมวดหลัก:

SQL Injection (SQLi): ดักจับ Tautology ด้วย Backreference (\b(OR|AND)\b\s+(['"]?\w+['"]?)\s*(=|>|<|LIKE)\s*\2), UNION [ALL] SELECT, Time-based functions (SLEEP, BENCHMARK, WAITFOR DELAY, PG_SLEEP), SQL Comments ร่วมกับ Quotes และคำสั่งอันตราย (DROP TABLE, DELETE FROM ฯลฯ)

Cross-Site Scripting (XSS): ดักจับแท็ก <script[^>]*>, HTML5 Event Handlers ทั้งหมด (\bon[a-zA-Z]+\s*=) และ javascript: URI

Path Traversal: ดักจับการปีนโฟลเดอร์ทั้ง Linux (../) และ Windows (..\) รวมถึงไฟล์ระบบสำคัญ (etc/passwd, win.ini, web.config, .env)

OS Command Injection: ดักจับตัวคั่นคำสั่ง (;, &, |, `, &&, ||) ตามด้วยคำสั่ง Shell ของทั้ง Linux และ Windows (cat, ls, dir, type, whoami, cmd, powershell, curl, wget, bash ฯลฯ)

BehaviorAnalyzer.java (รุ่นเริ่มต้น): นับจำนวน HTTP Error (401/404) สะสมต่อ IP เพื่อตรวจจับการสแกนไฟล์หรือ Brute-force เบื้องต้น




4. แผนการพัฒนายกระดับสู่ v1.0.0 (Feature Specifications & Roadmap)เพื่อให้ LogSentry สมบูรณ์ในฐานะเครื่องมือสแกน แกะรอย และใช้ยื่นสมัครงานได้จริง แผนการพัฒนาแบ่งออกเป็น 5 เฟสต่อเนื่องกัน ดังนี้:

Phase 1: ยกระดับโมเดลข้อมูลและมาตรฐานภัยคุกคาม (Data Model & MITRE ATT&CK)อัปเกรด LogEntry.java: เพิ่มฟิลด์สำคัญสำหรับงาน Forensics ได้แก่ responseBytes (ขนาดข้อมูลที่เซิร์ฟเวอร์ตอบกลับ) และ userAgent (ตัวระบุเบราว์เซอร์หรือเครื่องมือที่ใช้ยิง)MITRE ATT&CK Tagging: เพิ่มการติดป้ายรหัสยุทธวิธีและเทคนิคตามมาตรฐานสากลลงในผลการตรวจจับ เช่น:[T1190] Exploit Public-Facing Application (สำหรับ SQLi, Command Injection)
[T1059] Command and Scripting Interpreter (สำหรับ OS Command Injection)
[T1083] File and Directory Discovery (สำหรับ Path Traversal)
[T1595] Active Scanning (สำหรับ Directory Brute-force / 404 Burst)
[T1110] Brute Force (สำหรับ 401/403 Login Burst)


Phase 2: การวิเคราะห์เชิงพฤติกรรมและคณิตศาสตร์ (Stateful & Anomaly Detection)Sliding Time Window ใน BehaviorAnalyzer.java:แก้จุดอ่อนเดิมที่นับ Error สะสมตลอดกาลและเสี่ยงต่อ Memory Leakเปลี่ยนมาเก็บประวัติ Timestamp ของแต่ละ IP ด้วย Deque<Long> (ArrayDeque) เพื่อตรวจจับความถี่ภายในกรอบเวลา เช่น "เกิด HTTP 404 เกิน 5 ครั้ง ภายใน 10 วินาที"เพิ่มระบบ TTL / Eviction Cleanup ลบข้อมูล IP เก่าที่ไม่มีความเคลื่อนไหวออกจากหน่วยความจำอัตโนมัติAnomaly Detection ด้วย Shannon Entropy:คำนวณค่าความสุ่มของสตริง ($H(X) = -\sum p(x_i) \log_2 p(x_i)$) ใน Query Parametersหากพบพารามิเตอร์ที่มีค่า Entropy สูงผิดปกติ (เช่น > 4.5) ให้แจ้งเตือนว่าอาจมีการส่ง Obfuscated Payload, Base64/Hex Encoding หรือข้อมูลเข้ารหัสซ่อนเข้ามา


Phase 3: ระบบแกะรอยผู้โจมตีและสืบสวนไทม์ไลน์ (Incident Forensics)Kill Chain Timeline Reconstruction: สามารถดึงประวัติ Request ทั้งหมด ของ IP ต้องสงสัย (ทั้งบรรทัดที่ติด Alert และบรรทัดปกติ) มาเรียงตามลำดับเวลา เพื่อดูลำดับขั้นการโจมตีตั้งแต่ Recon $\rightarrow$ Probing $\rightarrow$ ExploitationBreach & Tool Fingerprinting:วิเคราะห์ User-Agent เพื่อระบุเครื่องมืออัตโนมัติ (เช่น sqlmap, Nikto, Gobuster, python-requests) เทียบกับเบราว์เซอร์คนทั่วไปประเมินผลกระทบจาก Status Code และ Response Bytes: หาก Payload โจมตีได้รับตอบกลับเป็น HTTP 200 OK ร่วมกับขนาดข้อมูลที่พุ่งสูงผิดปกติ ให้ติดสถานะ [CRITICAL] Potential Compromise / Data Exfiltration (แยกจาก 403/500 ที่เป็นเพียง Attempted)IP Threat Intelligence Lookup (Optional/Cached): เชื่อมต่อ API ภายนอก (เช่น ip-api.com หรือ AbuseIPDB) พร้อมทำ In-Memory Cache เพื่อสืบประเทศ (GeoIP), เครือข่าย (ASN/ISP) และตรวจสอบว่าเป็นเซิร์ฟเวอร์ Cloud/Data Center หรือไม่


Phase 4: โหมดการทำงาน CLI, Multi-Format Parser & External RulesDual-Mode & Investigation CLI (Main.java):java Main --tail <logfile> : โหมดเฝ้าระวังแบบ Real-timejava Main --scan <logfile> : โหมด Batch Audit สแกนไฟล์ Log ขนาดใหญ่ย้อนหลังตั้งแต่ต้นจนจบjava Main --investigate <IP> <logfile> : โหมดสืบสวนเจาะลึกเฉพาะ IP เป้าหมายและพิมพ์ Forensic ReportMulti-Format Log Parser (Strategy Pattern): สร้าง Interface LogParser เพื่อให้รองรับการอ่านทั้ง:CommonLogParser (Apache / Nginx / server.py format)JsonLogParser (Structured JSON Log ที่ส่งมาจาก EdgeGuard WAF และ AppShield RASP)Externalized Rules (rules.json): แยกกฎ Regex และแท็ก MITRE ATT&CK ออกจากโค้ด Java มาเก็บในไฟล์คอนฟิกภายนอก (เลียนแบบแนวคิด Sigma Rules) เพื่อให้เพิ่ม/แก้ไขกฎได้โดยไม่ต้อง Recompile โค้ดใหม่


Phase 5: การออกรายงาน แจ้งเตือน และมาตรฐานพอร์ตโฟลิโอ (Reporting, Testing & Docker)Audit Reporting & Webhook Alerting:ส่งออกสรุปผลการสแกนเป็นไฟล์ report.json (สรุปจำนวนภัยคุกคาม แยกตามประเภท และ Top Attacking IPs)ยิงแจ้งเตือนแบบ Real-time เข้า Discord / Slack Webhook ด้วย java.net.http.HttpClient เมื่อพบภัยคุกคามระดับ CriticalQuality Assurance & Benchmarking:เขียน Unit Tests (JUnit 5) วัด Detection Rate (ชุด Payload โจมตี) และ False Positive Rate (ทราฟฟิกปกติที่มีอักขระพิเศษ)ทำ Benchmark ทดสอบสแกน Log ขนาด 100,000 บรรทัดเพื่อเก็บตัวเลขเวลาประมวลผลลง README.mdContainerization: สร้าง Dockerfile และ docker-compose.yml สำหรับรัน LogSentry ร่วมกับ Mock Server และโปรเจกต์อื่นในระบบนิเวศ



5. โครงสร้างโฟลเดอร์เป้าหมาย (Target Project Structure)
Plaintext
LogSentry/
├── rules/
│   └── detection_rules.json      # กฎ Regex + รหัส MITRE ATT&CK (Externalized Rules)
├── mock_server/
│   ├── server.py                 # Python Mock Web Server สำหรับจำลองทราฟฟิกและสร้าง Log
│   └── access.log                # ไฟล์ Log เป้าหมาย
├── src/
│   ├── main/java/com/logsentry/
│   │   ├── Main.java                 # CLI Entrypoint (--tail, --scan, --investigate)
│   │   ├── model/
│   │   │   ├── LogEntry.java         # โครงสร้างข้อมูล Log (IP, Time, Method, URI, Status, Bytes, UA)
│   │   │   ├── ThreatAlert.java      # โครงสร้างผลการตรวจจับ (Rule, Severity, MITRE ID, Breach Status)
│   │   │   └── DetectionRule.java    # โมเดลกฎที่โหลดมาจาก JSON
│   │   ├── parser/
│   │   │   ├── LogParser.java        # Interface สำหรับ Strategy Pattern
│   │   │   ├── CommonLogParser.java  # ตัวแปลง Log รูปแบบมาตรฐานเว็บเซิร์ฟเวอร์
│   │   │   └── JsonLogParser.java    # ตัวแปลง JSON Log จาก EdgeGuard WAF / AppShield RASP
│   │   ├── engine/
│   │   │   ├── LogSanitizer.java     # ถอดรหัส URL Encoding หลายชั้น & Normalization
│   │   │   ├── ThreatDetector.java   # ตัวตรวจจับ Signature (Regex) + Shannon Entropy
│   │   │   └── BehaviorAnalyzer.java # ตัวตรวจจับพฤติกรรมแบบ Sliding Time Window (Deque)
│   │   ├── forensics/
│   │   │   ├── TimelineBuilder.java  # แกะรอย Kill Chain ของ IP เป้าหมาย
│   │   │   └── ThreatIntelClient.java# เช็ก GeoIP / ASN พร้อมระบบ Cache
│   │   └── output/
│   │       ├── ReportGenerator.java  # สรุปผลและ Export เป็นไฟล์ JSON / Console Report
│   │       └── WebhookNotifier.java  # ส่งแจ้งเตือนเข้า Discord / Slack
│   └── test/java/com/logsentry/      # ชุดทดสอบ JUnit 5 (Detection Rate, False Positive, Benchmark)
├── Dockerfile
├── docker-compose.yml
├── PROJECT_SPEC.md                   # เอกสารฉบับนี้
└── README.md                         # เอกสารโชว์สถาปัตยกรรม ผล Benchmark และวิธีใช้งานสำหรับพอร์ตโฟลิโอ