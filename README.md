# 🛡️ LogSentry

(โปรเจคนี้ทำในกรณีศึกษา)
**LogSentry** คือ Security Library ภาษา Java ขนาดเล็กที่ผมเขียนขึ้นมาเพื่อลองทำระบบวิเคราะห์ Web Server Access Log และตรวจจับภัยคุกคามไซเบอร์อัตโนมัติ (Automated Threat Detection) 

เน้นการออกแบบสถาปัตยกรรมโค้ดตามหลัก **Object-Oriented Programming (OOP)** เพื่อให้ขยายต่อ (Scale) ได้ง่ายในอนาคต

---

## ทำอะไรได้บ้าง?

* **แกะ Log ดิบ (Log Parsing):** อ่าน Web Server Access Log (เช่น Combined Format) แล้วแยก IP, Request URL และ HTTP Status Code ออกมาเป็น Object
* **อ่านไฟล์จริงจาก Disk:** ดึงไฟล์ `.log` จากระบบเข้ามาประมวลผลทีละบรรทัด (Line-by-Line) ไม่กิน Memory ด้วย `BufferedReader`
* **สแกนหาภัยคุกคามเบื้องต้น:**
  *  **SQL Injection (SQLi)** — ตรวจจับคำสั่งและรูปแบบ SQL ที่น่าสงสัย
  *  **Cross-Site Scripting (XSS)** — ตรวจจับการพยายามฝัง Payload / Script แปลกปลอม
  *  **Path Traversal** — ตรวจจับการพยายามแอบอ่านไฟล์สำคัญในเครื่อง (เช่น `/etc/passwd`)

---

## 🏗️ โครงสร้างโปรเจกต์
LogSentry /
├── LogEntry.java        # Data Model สำหรับแกะและเก็บข้อมูล Log
├── LogFileReader.java    # ตัวอ่านไฟล์ .log จาก Disk เข้ามาประมวลผล
├── ThreatDetector.java   # สมองส่วนวิเคราะห์และเก็บ Security Rules
├── Main.java             # ตัวรันสำหรับทดสอบระบบ
└── access.log            # ไฟล์ Log ดิบที่ใช้ทดสอบจริง