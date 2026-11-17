package com.logsentry.engine;

import com.logsentry.model.LogEntry;
import com.logsentry.model.ThreatAlert;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class BehaviorAnalyzer {

    // รูปแบบ Timestamp มาตรฐานของ Apache/Nginx Log เช่น 15/Nov/2026:19:00:44 +0700
    private static final DateTimeFormatter LOG_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    // เก็บประวัติเวลา (Timestamps) ของแต่ละ IP แยกตามประเภทเหตุการณ์
    private final Map<String, Deque<Instant>> failedLoginHistory = new HashMap<>();
    private final Map<String, Deque<Instant>> notFoundHistory = new HashMap<>();

    // เกณฑ์การแจ้งเตือนภายในกรอบเวลา (Sliding Window)
    private static final long WINDOW_SECONDS = 10;
    private static final int BRUTE_FORCE_THRESHOLD = 3;
    private static final int SCAN_THRESHOLD = 3;

    public List<ThreatAlert> analyzeBehavior(LogEntry entry) {
        List<ThreatAlert> alerts = new ArrayList<>();
        String ip = entry.getIp();
        int statusCode = entry.getStatusCode();
        Instant eventTime = parseLogTimestamp(entry.getTimestamp());

        // 1. ตรวจจับ Password Brute Force (HTTP 401 ภายใน 10 วินาที) -> MITRE T1110
        if (statusCode == 401) {
            int recentCount = recordAndCountInWindow(failedLoginHistory, ip, eventTime);
            if (recentCount >= BRUTE_FORCE_THRESHOLD && recentCount % BRUTE_FORCE_THRESHOLD == 0) {
                String detail = String.format("Password Brute Force (%d failed logins within %ds)",
                        recentCount, WINDOW_SECONDS);
                alerts.add(new ThreatAlert(detail, "T1110", "Credential Access", "HIGH", false));
            }
        }

        // 2. ตรวจจับ Directory / Path Scanning (HTTP 404 ภายใน 10 วินาที) -> MITRE T1595.003
        if (statusCode == 404) {
            int recentCount = recordAndCountInWindow(notFoundHistory, ip, eventTime);
            if (recentCount >= SCAN_THRESHOLD && recentCount % SCAN_THRESHOLD == 0) {
                String detail = String.format("Directory / Path Scanning (%d 404 errors within %ds)",
                        recentCount, WINDOW_SECONDS);
                alerts.add(new ThreatAlert(detail, "T1595.003", "Reconnaissance", "MEDIUM", false));
            }
        }

        return alerts;
    }

    // บันทึกเวลาปัจจุบันและตัดรายการที่เก่าเกินกรอบเวลา (Sliding Window) ทิ้ง
    private int recordAndCountInWindow(Map<String, Deque<Instant>> historyMap, String ip, Instant currentTime) {
        Deque<Instant> timestamps = historyMap.computeIfAbsent(ip, k -> new ArrayDeque<>());

        // ลบรายการที่อยู่นอกกรอบเวลา 10 วินาทีออกจากหัวคิว
        while (!timestamps.isEmpty()) {
            long diffSeconds = Duration.between(timestamps.peekFirst(), currentTime).getSeconds();
            if (diffSeconds > WINDOW_SECONDS) {
                timestamps.pollFirst();
            } else {
                break;
            }
        }

        timestamps.addLast(currentTime);
        return timestamps.size();
    }

    // แปลง String เวลาจาก Log เป็น Instant สำหรับคำนวณระยะห่าง
    private Instant parseLogTimestamp(String timestampStr) {
        try {
            return ZonedDateTime.parse(timestampStr, LOG_TIME_FORMATTER).toInstant();
        } catch (DateTimeParseException e) {
            return Instant.now();
        }
    }
}