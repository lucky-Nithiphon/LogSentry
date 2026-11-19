> **⚠️ Educational Purpose Disclaimer:**  
> **LogSentry** เป็นโปรเจกต์ที่ผมพัฒนาขึ้นเพื่อการศึกษา วิจัย และฝึกฝนทักษะด้าน Cybersecurity & Software Engineering เท่านั้น โค้ดและกฎการตรวจจับทั้งหมดออกแบบมาสำหรับการเรียนรู้และทดสอบในสภาพแวดล้อมจำลอง

<div align="center">

# 🛡️ LogSentry
### Out-of-Band Mini-SIEM & Automated Log Forensics Engine

![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![Python](https://img.shields.io/badge/Mock_Target-Python_3-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Framework](https://img.shields.io/badge/MITRE-ATT%26CK_Mapped-B80000?style=for-the-badge)
![Version](https://img.shields.io/badge/Release-v1.1.0-2EA44F?style=for-the-badge)

**LogSentry** คือระบบตรวจจับภัยคุกคามและวิเคราะห์หลักฐานทางดิจิทัล (Mini-SIEM & Forensics Engine) พัฒนาด้วยภาษา **Java** ออกแบบมาเพื่อทำงานเป็นชั้น **Out-of-Band Detection & Incident Investigation** ในสถาปัตยกรรมป้องกันเชิงลึก (**Defense-in-Depth**)

</div>

---

## 🏗️ Defense-in-Depth Ecosystem

โปรเจกต์นี้เป็นส่วนหนึ่งของชุดระบบความปลอดภัยแบบหลายชั้น (Multi-Layered Security Architecture) ที่ออกแบบให้ทำงานประสานกันตั้งแต่หน้าด่านจนถึงระดับแอปพลิเคชัน:

```text
                        [ Internet / Attacker ]
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  1. EdgeGuard WAF (Go Reverse Proxy)                                │
│     • Inline Perimeter Defense, Rate Limiting & Fast-Path Filtering │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  2. AppShield RASP (Python ASGI Middleware)                         │
│     • Runtime Context-Aware Guard (IDOR, Mass Assignment, DLP)      │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                    [ Access Logs / JSON Telemetry ]
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  3. LogSentry (Java Mini-SIEM)  ◀── [ CURRENT REPOSITORY ]          │
│     • Out-of-Band Log Correlation, Entropy Analysis & Forensics     │
└─────────────────────────────────────────────────────────────────────┘
```

* **EdgeGuard WAF (Go):** ปราการด่านหน้าแบบ Inline Reverse Proxy กรองทราฟฟิกความเร็วสูงและทำ Rate Limiting ก่อนถึงเว็บหลัก
* **AppShield RASP (Python):** ไลบรารีป้องกันระดับ Runtime ฝังใน FastAPI ดักจับช่องโหว่เชิงตรรกะและข้อมูลรั่วไหล
* **LogSentry (Java):** ศูนย์วิเคราะห์ Log ย้อนหลังและ Real-time ทำหน้าที่ถอดรหัสการโจมตี, ติดป้าย MITRE ATT&CK, แกะรอยไทม์ไลน์ผู้บุกรุก และออกรายงาน `report.json`

---

## ⚙️ Internal Pipeline Architecture

```text
access.log / waf.jsonl
       │
       ▼
[LogFileReader / Batch Reader]
       │
       ▼ (Auto-Format Detection)
[LogParser (Strategy Pattern)] ──► CommonLogParser (Apache/Nginx)
       │                       ──► JsonLogParser   (EdgeGuard WAF / AppShield RASP)
       ▼
 [LogEntry Model]
       │
       ├──► [ThreatDetector]   (Multi-layer URL Decode + MITRE ATT&CK + Breach Check)
       ├──► [EntropyAnalyzer]  (Shannon Entropy Calculation -> T1027 Obfuscation)
       └──► [BehaviorAnalyzer] (Sliding Time Window 10s -> Dir Scan / Brute Force)
       │
       ▼
[TimelineBuilder] ──► จัดกลุ่มเหตุการณ์ตาม Attacker IP & เรียง Kill Chain
       │
       ▼
[JsonReportExporter] ──► ส่งออกรายงานนิติเวชดิจิทัล (report.json)
```

---

## 🔍 Detection Capabilities & MITRE ATT&CK Mapping

| Attack Vector | Detection Technique | MITRE ATT&CK | Severity & Breach Logic |
| :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Iterative URL Decode + Tautology, `UNION SELECT`, Time-based Regex | `T1190` *(Initial Access)* | `CRITICAL` if HTTP 200, else `HIGH` |
| **Cross-Site Scripting (XSS)** | `<script>`, HTML5 Event Handlers (`onerror=`, `onload=`), `javascript:` URI | `T1059.007` *(Execution)* | `HIGH` (+ Breach Flag if HTTP 200) |
| **Path Traversal** | Directory Climbing (`../`, `..\`) & Sensitive Files (`/etc/passwd`, `.env`) | `T1083` *(Discovery)* | `CRITICAL` if HTTP 200, else `HIGH` |
| **OS Command Injection** | Command Chaining (`;`, `&&`, `\|`, `` ` ``) + System Binaries (`cat`, `whoami`, `dir`) | `T1059` *(Execution)* | `CRITICAL` |
| **Obfuscated Payloads** | Shannon Entropy Scoring ($H(X) \ge 4.5$) on Long Query Parameters (`Base64`/`Hex`) | `T1027` *(Defense Evasion)* | `MEDIUM` (+ Breach Flag if HTTP 200) |
| **Directory / Path Scanning** | Stateful Sliding Time Window ($\ge 3$ `HTTP 404` responses within 10s) | `T1595.003` *(Reconnaissance)* | `MEDIUM` |
| **Brute-Force Login** | Stateful Sliding Time Window ($\ge 5$ `HTTP 401/403` responses within 10s) | `T1110` *(Credential Access)* | `HIGH` |
| **Automated Recon Tools** | `User-Agent` Fingerprinting (`sqlmap`, `nikto`, `gobuster`, `ffuf`, `nuclei`) | `T1595` *(Reconnaissance)* | `MEDIUM` |

---

## 📖 คู่มือการใช้งาน (User Guide & CLI Commands)

### 1. การเตรียมระบบและคอมไพล์ (Prerequisites & Build)
* **Java Development Kit (JDK):** เวอร์ชัน 17 ขึ้นไป
* **Python 3:** สำหรับรันเว็บเซิร์ฟเวอร์จำลอง (`mock_server/server.py`) ในการทดสอบ

เปิด Terminal ในโฟลเดอร์โปรเจกต์ แล้วคอมไพล์โค้ดทั้งหมด:
```powershell
javac -d out (Get-ChildItem -Recurse -Filter *.java src).FullName
```

### 2. โหมดเมนูโต้ตอบ (Interactive CLI Menu — แนะนำ)
รันโปรแกรมโดยไม่ต้องใส่พารามิเตอร์ เพื่อเปิดหน้าเมนูตัวเลขสำหรับเลือกโหมดใช้งาน:
```powershell
# บน Windows PowerShell (แนะนำให้ใช้สคริปต์ตัวช่วยเพื่อรองรับ UTF-8 อัตโนมัติ)
.\logsentry.ps1

# หรือรันผ่าน Java โดยตรง
java -cp out com.logsentry.Main
```
```text
============================================================
🛡️  LogSentry v1.1.0 — Out-of-Band Mini-SIEM & Forensics
============================================================
   [1] 📡 Real-time Monitor  (เฝ้าดูไฟล์ Log แบบสด)
   [2] 🔍 Batch Audit Scan   (สแกนไฟล์ Log ย้อนหลังทั้งไฟล์)
   [3] 🎯 Investigate IP     (แกะรอยไทม์ไลน์ทั้งหมดของ IP เป้าหมาย)
   [4] 📖 Help               (ดูคู่มือคำสั่ง CLI)
   [0] ❌ Exit               (ออกจากโปรแกรม)
============================================================
```

### 3. คำสั่ง CLI สำหรับรันตรง (Direct CLI Arguments)

| คำสั่ง | คำอธิบายการทำงาน |
| :--- | :--- |
| `.\logsentry.ps1 --tail [logfile]` | เฝ้าดูไฟล์ Log แบบ Real-time (ค่าเริ่มต้น: `mock_server/access.log`) กด `Ctrl + C` เพื่อสรุปไทม์ไลน์และสร้าง `report.json` |
| `.\logsentry.ps1 --scan [logfile]` | สแกนไฟล์ Log ย้อนหลังตั้งแต่ต้นจนจบ สรุปผลบนหน้าจอ และส่งออก `report.json` ทันที |
| `.\logsentry.ps1 --investigate <IP> [logfile]` | ดึงประวัติคำขอ **ทั้งหมด** (ทั้งปกติ `[CLEAN]` และโจมตี `[ALERT]`) ของ IP เป้าหมายมาเรียง Kill Chain ตามลำดับเวลา |
| `.\logsentry.ps1 --help` | แสดงคู่มือคำสั่งทั้งหมดบนหน้าจอ Terminal |

*(หมายเหตุ: บน Linux/macOS สามารถใช้คำสั่ง `java -cp out com.logsentry.Main <arguments>` แทน `.\logsentry.ps1` ได้ทันที)*

### 4. การรันผ่าน Docker Container
```bash
# สร้าง Image
docker build -t logsentry:1.1.0 .

# รันโหมดเฝ้าระวังไฟล์ Log ที่แชร์ผ่าน Volume
docker run --rm -v "$(pwd)/mock_server:/logs" logsentry:1.1.0 --tail /logs/access.log
```

---

## 🧪 การทดสอบจำลองการโจมตี (Red Team Simulation)

1. **เปิดเว็บเป้าหมายจำลอง (Terminal 1):**
   ```powershell
   python mock_server/server.py
   ```
2. **เปิด LogSentry เฝ้าระวัง (Terminal 2):**
   ```powershell
   .\logsentry.ps1 --tail
   ```
3. **ยิง Payload ทดสอบการตรวจจับแต่ละรูปแบบ (Terminal 3):**
   ```powershell
   # 1. ทดสอบ SQL Injection + เครื่องมือ sqlmap (T1190, T1595 & Potential Breach)
   curl.exe -A "sqlmap/1.8" "[http://127.0.0.1:8000/index.html?id=1%20UNION%20SELECT%201,2,3](http://127.0.0.1:8000/index.html?id=1%20UNION%20SELECT%201,2,3)"

   # 2. ทดสอบ Payload เข้ารหัส Base64 ความสุ่มสูง (T1027 Shannon Entropy)
   curl.exe "[http://127.0.0.1:8000/index.html?data=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0](http://127.0.0.1:8000/index.html?data=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0)"

   # 3. ทดสอบไล่สแกนหาไฟล์ลับรัวๆ ภายใน 10 วินาที (T1083 & T1595.003 Sliding Window)
   curl.exe "[http://127.0.0.1:8000/admin](http://127.0.0.1:8000/admin)"
   curl.exe "[http://127.0.0.1:8000/.env](http://127.0.0.1:8000/.env)"
   curl.exe "[http://127.0.0.1:8000/backup.zip](http://127.0.0.1:8000/backup.zip)"
   ```

---

## 📂 Project Structure

```text
LogSentry/
├── src/com/logsentry/
│   ├── Main.java                      # Entry Point, Interactive Menu & CLI Orchestrator
│   ├── model/
│   │   ├── LogEntry.java              # Immutable Forensics Log Data Model
│   │   └── ThreatAlert.java           # SOC Alert Model (MITRE ATT&CK + Breach Indicator)
│   ├── parser/
│   │   ├── LogParser.java             # Strategy Interface for Multi-Format Ingestion
│   │   ├── CommonLogParser.java       # Apache/Nginx Combined Log Format Parser
│   │   ├── JsonLogParser.java         # Structured JSON Telemetry Parser (WAF/RASP)
│   │   └── LogFileReader.java         # Non-blocking Real-time Log Tailer
│   ├── engine/
│   │   ├── LogSanitizer.java          # Iterative URL Decoder (Anti-Double/Triple Encoding)
│   │   ├── ThreatDetector.java        # Signature & User-Agent Detection Engine
│   │   ├── EntropyAnalyzer.java       # Shannon Entropy Calculator for Obfuscated Payloads
│   │   └── BehaviorAnalyzer.java      # Stateful Sliding Time Window Frequency Analyzer
│   ├── forensics/
│   │   └── TimelineBuilder.java       # Per-IP Incident & Kill Chain Reconstructor
│   └── output/
│       └── JsonReportExporter.java    # Pure-Java Structured JSON Report Generator
├── mock_server/
│   ├── server.py                      # Vulnerable Target Web Server (Combined Log Emitter)
│   ├── index.html                     # Target Landing Page
│   └── access.log                     # Live Access Log Stream
├── Dockerfile                         # Container Build Configuration
└── logsentry.ps1                      # PowerShell UTF-8 Wrapper Script
```

---

## 📜 Version History (Changelog)

* **`v1.1.0` — Interactive CLI & IP Investigation:** เพิ่มหน้าเมนูโต้ตอบ (Interactive CLI Menu), โหมดเจาะสืบสวนราย IP (`--investigate`), คู่มือ `--help`, ระบบบังคับ UTF-8 ในตัว และสคริปต์ทางลัด `logsentry.ps1`
* **`v1.0.0` — Multi-Source SIEM Integration (Phase 4):** เพิ่ม `JsonLogParser` รองรับ Structured JSON Log จาก **EdgeGuard WAF** และ **AppShield RASP**, เพิ่มโหมดสแกนย้อนหลัง (`--scan`) และ `Dockerfile`
* **`v0.7.0` — Automated Forensics & Reporting (Phase 3):** สร้าง `TimelineBuilder` เรียงไทม์ไลน์เหตุการณ์แยกตาม IP และ `JsonReportExporter` ส่งออกรายงาน `report.json` อัตโนมัติ
* **`v0.6.0` — Advanced Detection Engine (Phase 2):** เพิ่ม `EntropyAnalyzer` คำนวณค่า Shannon Entropy (`T1027`) และอัปเกรด `BehaviorAnalyzer` ให้ใช้ Sliding Time Window 10 วินาที
* **`v0.5.0` — Modular Architecture & MITRE ATT&CK (Phase 1):** แยกโครงสร้างแพ็กเกจ OOP, เก็บข้อมูล Forensics (`Bytes`, `User-Agent`) และติดป้ายรหัส MITRE ATT&CK พร้อมตัวชี้วัด `POTENTIAL BREACH`
* **`v0.1.0` — Initial Prototype:** ระบบอ่าน Log แบบ Real-time, ตัวถอดรหัส URL หลายชั้น (`LogSanitizer`) และกฎตรวจจับการโจมตีพื้นฐาน