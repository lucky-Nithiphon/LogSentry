import http.server
import socketserver
from datetime import datetime
import os

PORT = 8000
LOG_FILE = "access.log"

class VulnerableTargetHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        client_ip = self.client_address[0]
        time_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0700")
        request_line = self.requestline
        status_code = str(args[1])

        # ดึงข้อมูล User-Agent และ Referer จาก HTTP Headers
        user_agent = self.headers.get("User-Agent", "-")
        referer = self.headers.get("Referer", "-")

        # คำนวณขนาดข้อมูลตอบกลับโดยประมาณ (จำลองพฤติกรรมเซิร์ฟเวอร์จริง)
        if status_code == "200":
            # จำลองว่าหากยิง SQLi/Dump แล้วได้ 200 OK ข้อมูลจะหลุดออกมาก้อนใหญ่
            if any(k in request_line.upper() for k in ["UNION", "SELECT", "OR%201=1", "OR+1=1"]):
                response_bytes = 15420
            else:
                response_bytes = 1024
        else:
            response_bytes = 512

        # บันทึกตามมาตรฐาน Combined Log Format
        log_entry = (
            f'{client_ip} - - [{time_str}] "{request_line}" '
            f'{status_code} {response_bytes} "{referer}" "{user_agent}"\n'
        )

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
        print(f"[Web Logged]: {request_line} -> Status {status_code} ({response_bytes}B) | UA: {user_agent}")

os.chdir(os.path.dirname(os.path.abspath(__file__)))
print(f"[+] เซิร์ฟเวอร์เป้าหมายรันที่ http://localhost:{PORT}")
print(f"[+] เขียน Log ออกไปที่: {os.path.abspath(LOG_FILE)}")

with socketserver.TCPServer(("", PORT), VulnerableTargetHandler) as httpd:
    httpd.serve_forever()