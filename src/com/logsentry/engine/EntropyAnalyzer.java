package com.logsentry.engine;

import com.logsentry.model.LogEntry;
import com.logsentry.model.ThreatAlert;
import java.util.HashMap;
import java.util.Map;

public class EntropyAnalyzer {

    // เกณฑ์มาตรฐานสำหรับตรวจจับข้อความเข้ารหัส (Base64 / Hex / Obfuscated Payload)
    private static final int MIN_LENGTH_TO_CHECK = 24;
    private static final double ENTROPY_THRESHOLD = 4.5;

    public ThreatAlert analyze(LogEntry entry) {
        String cleanRequest = LogSanitizer.sanitize(entry.getRequest());

        // แยกส่วน Query String หลังเครื่องหมาย ? มาตรวจสอบทีละพารามิเตอร์
        int queryIndex = cleanRequest.indexOf('?');
        if (queryIndex == -1 || queryIndex == cleanRequest.length() - 1) {
            return null;
        }

        String queryString = cleanRequest.substring(queryIndex + 1);
        String[] params = queryString.split("&");

        for (String param : params) {
            int eqIndex = param.indexOf('=');
            String value = (eqIndex != -1) ? param.substring(eqIndex + 1) : param;

            // ตรวจเฉพาะค่าที่มีความยาวมากพอ เพื่อป้องกัน False Positive กับคำสั้นๆ
            if (value.length() >= MIN_LENGTH_TO_CHECK) {
                double entropy = calculateShannonEntropy(value);
                if (entropy >= ENTROPY_THRESHOLD) {
                    boolean isHttp200 = (entry.getStatusCode() == 200);
                    String detail = String.format("High Entropy Payload Detected (Score: %.2f)", entropy);
                    return new ThreatAlert(detail, "T1027", "Defense Evasion", "MEDIUM", isHttp200);
                }
            }
        }

        return null;
    }

    // สูตรคำนวณ Shannon Entropy: H(X) = -Sum(P(x) * log2(P(x)))
    public static double calculateShannonEntropy(String input) {
        if (input == null || input.isEmpty()) {
            return 0.0;
        }

        Map<Character, Integer> freqMap = new HashMap<>();
        for (char c : input.toCharArray()) {
            freqMap.put(c, freqMap.getOrDefault(c, 0) + 1);
        }

        double entropy = 0.0;
        int len = input.length();

        for (int count : freqMap.values()) {
            double probability = (double) count / len;
            // แปลงฐานลอการิทึมจากฐาน e เป็นฐาน 2 ด้วย Math.log(p) / Math.log(2)
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return entropy;
    }
}