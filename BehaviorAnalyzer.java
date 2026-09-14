// ดักจับพฤติกรรมที่ผิดปกติจาก Log
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BehaviorAnalyzer {

    // เก็บจำนวนครั้งที่ IP เจอรหัส 401 (Unauthorized)
    private Map<String, Integer> failedLoginCounts = new HashMap<>();

    // เก็บจำนวนครั้งที่ IP เจอรหัส 404 (Not Found)
    private Map<String, Integer> notFoundCounts = new HashMap<>();

    // เกณฑ์การแจ้งเตือน (Thresholds)
    private static final int BRUTE_FORCE_THRESHOLD = 3;
    private static final int SCAN_THRESHOLD = 3;

    public List<String> analyzeBehavior(LogEntry entry) {
        List<String> threats = new ArrayList<>();
        String ip = entry.getIp();
        int statusCode = entry.getStatusCode();

        // 1. ตรวจจับ Password Brute Force (HTTP 401)
        if (statusCode == 401) {
            int count = failedLoginCounts.getOrDefault(ip, 0) + 1;
            failedLoginCounts.put(ip, count);

            // 💡 แก้ไข Logic: แจ้งเตือนเมื่อแตะ Threshold พอดี (==) หรือเมื่อถึงจุดที่กำหนด
            if (count == BRUTE_FORCE_THRESHOLD) {
                threats.add("Possible Password Brute Force (Reached threshold: " + count + " failed attempts)");
            }
        }

        // 2. ตรวจจับ Directory / Path Scanning (HTTP 404)
        if (statusCode == 404) {
            int count = notFoundCounts.getOrDefault(ip, 0) + 1;
            notFoundCounts.put(ip, count);

            // 💡 แก้ไข Logic: แจ้งเตือนเมื่อแตะ Threshold พอดี (==)
            if (count == SCAN_THRESHOLD) {
                threats.add("Possible Directory Scanning (Reached threshold: " + count + " 404 Not Found status)");
            }
        }

        return threats;
    }
}