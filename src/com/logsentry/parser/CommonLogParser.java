package com.logsentry.parser;

import com.logsentry.model.LogEntry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CommonLogParser implements LogParser {

    // รองรับทั้ง Common Log Format และ Combined Log Format (ที่มี Referer & User-Agent ต่อท้าย)
    private static final Pattern COMBINED_LOG_PATTERN = Pattern.compile(
            "^(\\S+)\\s+\\S+\\s+\\S+\\s+\\[([^\\]]+)\\]\\s+\"([^\"]+)\"\\s+(\\d{3})\\s+(\\d+|-)(?:\\s+\"([^\"]*)\"\\s+\"([^\"]*)\")?$"
    );

    @Override
    public LogEntry parse(String rawLine) {
        if (rawLine == null || rawLine.trim().isEmpty()) {
            return null;
        }

        Matcher matcher = COMBINED_LOG_PATTERN.matcher(rawLine.trim());
        if (!matcher.matches()) {
            return null;
        }

        String ip = matcher.group(1);
        String timestamp = matcher.group(2);
        String fullRequestLine = matcher.group(3);
        int statusCode = Integer.parseInt(matcher.group(4));

        String bytesStr = matcher.group(5);
        long responseBytes = bytesStr.equals("-") ? 0L : Long.parseLong(bytesStr);

        String userAgent = matcher.group(7); // Group 6 คือ Referer, Group 7 คือ User-Agent

        // แยก HTTP Method และ Path/Query ออกจาก "GET /index.html HTTP/1.1"
        String method = "UNKNOWN";
        String requestPath = fullRequestLine;
        String[] reqParts = fullRequestLine.split("\\s+");
        if (reqParts.length >= 3) {
            method = reqParts[0];
            requestPath = fullRequestLine.substring(method.length() + 1, fullRequestLine.lastIndexOf(' '));
        } else if (reqParts.length == 2) {
            method = reqParts[0];
            requestPath = reqParts[1];
        }

        return new LogEntry(ip, timestamp, method, requestPath, statusCode, responseBytes, userAgent, rawLine);
    }
}