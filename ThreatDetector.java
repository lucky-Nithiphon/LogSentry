// ส่วนวิเคราะห์และตรวจสอบการโดนโจมตี

import java.util.ArrayList;
import java.util.List;

public class ThreatDetector {

    // ฟังก์ชันสำหรับวิเคราะห์ LogEntry และส่งคืนรายการภัยคุกคามที่ตรวจเจอ
    public List<String> analyze(LogEntry entry) {

        List<String> threats = new ArrayList<>();  // สร้าง List เปล่าสำหรับเก็บชื่อการโจมตีที่ตรวจพบ

        String cleanRequest = LogSanitizer.sanitize(entry.getRequest()); // เอา Request มาผ่าน LogSanitizer ถอดรหัสให้คลีนก่อนสแกน
        
        // ดึงข้อความ Request มาแปลงเป็นตัวพิมพ์ใหญ่ และตัวพิมพ์เล็ก เพื่อให้ง่ายต่อการเช็ก
        String reqUpper = cleanRequest.toUpperCase();
        String reqLower = cleanRequest.toLowerCase();

        // Rule 1: ตรวจจับ SQL Injection (SQLi)
        // เช็กว่ามีคำสั่ง SQL อันตราย เช่น OR 1=1 หรือ UNION SELECT 
        if (reqUpper.contains("OR 1=1") || reqUpper.contains("UNION SELECT") || reqUpper.contains("SELECT") && reqUpper.contains("FROM") || reqUpper.contains("DROP TABLE") || reqUpper.contains("INSERT INTO")) {
            threats.add("SQL Injection (SQLi)");
        }
        
        // Rule 2: ตรวจจับ Cross-Site Scripting (XSS)
        // เช็กว่ามีการพยายามฝัง Code HTML/JavaScript เช่น <script> หรือ javascript: 
        if (reqLower.contains(("<script>")) || reqLower.contains("javascript:") || reqLower.contains("onerror=") || reqLower.contains("onload=") ||  reqLower.contains("document.cookie")){
            threats.add("Cross-Site Scripting (XSS)");
        }
        
        // Rule 3: ตรวจจับ Path Traversal
        // เช็กว่ามีการพยายามแอบดูไฟล์ในระบบ เช่น ../ หรือ /etc/passwd
        if (reqLower.contains("/etc/passwd") || reqLower.contains("../")){
            threats.add("Path Traversal Attempt");
        }
        
        // 4. Rule: OS Command Injection (ดักจับคำสั่งระบบปฏิบัติการ)
        if (reqLower.contains("; cat ") || reqLower.contains("| cat ") || reqLower.contains("; ls") || reqLower.contains("cmd.exe")){
            threats.add("OS Command Injection");
        }
  
        //คืนค่า List ของภัยคุกคามที่เจอ
        return threats;
    }
}
