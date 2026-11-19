package com.logsentry.parser;

import com.logsentry.model.LogEntry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JsonLogParser implements LogParser {

    @Override
    public LogEntry parse(String rawLine) {
        if (rawLine == null) {
            return null;
        }
        String trimmed = rawLine.replace("\uFEFF", "").trim();
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
            return null;
        }

        // ดึงฟิลด์มาตรฐานตาม Ecosystem Integration Contract (EdgeGuard WAF / AppShield RASP)
        String ip = extractStringField(trimmed, "client_ip");
        if (ip == null) {
            ip = extractStringField(trimmed, "ip");
        }
        if (ip == null) {
            return null; // หากไม่มี IP ถือว่าไม่ใช่ Event Log ที่สมบูรณ์
        }

        String timestamp = extractStringField(trimmed, "timestamp");
        if (timestamp == null) timestamp = "UNKNOWN_TIME";

        String method = extractStringField(trimmed, "method");
        if (method == null) method = "UNKNOWN";

        String path = extractStringField(trimmed, "path");
        if (path == null) path = "/";

        // หาก WAF/RASP แนบ payload หรือ query ที่ตรวจพบมาด้วย ให้ต่อท้าย path เพื่อให้เอนจินวิเคราะห์ต่อได้
        String payload = extractStringField(trimmed, "payload");
        if (payload != null && !payload.isEmpty() && !path.contains("?")) {
            path = path + "?payload=" + payload;
        }

        int statusCode = extractIntField(trimmed, "status_code", 200);
        long responseBytes = extractLongField(trimmed, "response_bytes", 0L);

        // ระบุแหล่งที่มา (เช่น edgeguard-waf หรือ appshield-rasp) ในช่อง User-Agent หากไม่มี user_agent ตรงๆ
        String userAgent = extractStringField(trimmed, "user_agent");
        if (userAgent == null) {
            String source = extractStringField(trimmed, "source");
            String ruleId = extractStringField(trimmed, "rule_id");
            if (source != null && ruleId != null) {
                userAgent = source + " (" + ruleId + ")";
            } else if (source != null) {
                userAgent = source;
            }
        }

        return new LogEntry(ip, timestamp, method, path, statusCode, responseBytes, userAgent, rawLine);
    }

    private String extractStringField(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:\\\\\"|[^\"])*)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1).replace("\\\"", "\"").replace("\\\\", "\\");
        }
        return null;
    }

    private int extractIntField(String json, String key, int defaultValue) {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            try {
                return Integer.parseInt(matcher.group(1));
            } catch (NumberFormatException ignored) {
            }
        }
        return defaultValue;
    }

    private long extractLongField(String json, String key, long defaultValue) {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            try {
                return Long.parseLong(matcher.group(1));
            } catch (NumberFormatException ignored) {
            }
        }
        return defaultValue;
    }
}