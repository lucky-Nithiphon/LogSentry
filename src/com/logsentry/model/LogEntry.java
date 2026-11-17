package com.logsentry.model;

public class LogEntry {
    private final String ip;
    private final String timestamp;
    private final String method;
    private final String request;
    private final int statusCode;
    private final long responseBytes;
    private final String userAgent;
    private final String rawLine;

    // Constructor เดิม (รองรับโค้ดเก่าไม่ให้พังระหว่างอัปเกรด)
    public LogEntry(String ip, String timestamp, String method, String request, int statusCode) {
        this(ip, timestamp, method, request, statusCode, 0L, "Unknown", "");
    }

    // Constructor ใหม่แบบเต็มสำหรับงาน Incident Forensics
    public LogEntry(String ip, String timestamp, String method, String request,
                    int statusCode, long responseBytes, String userAgent, String rawLine) {
        this.ip = ip;
        this.timestamp = timestamp;
        this.method = method;
        this.request = request;
        this.statusCode = statusCode;
        this.responseBytes = responseBytes;
        this.userAgent = (userAgent == null || userAgent.isEmpty()) ? "Unknown" : userAgent;
        this.rawLine = (rawLine == null) ? "" : rawLine;
    }

    public String getIp() { return ip; }
    public String getTimestamp() { return timestamp; }
    public String getMethod() { return method; }
    public String getRequest() { return request; }
    public int getStatusCode() { return statusCode; }
    public long getResponseBytes() { return responseBytes; }
    public String getUserAgent() { return userAgent; }
    public String getRawLine() { return rawLine; }

    @Override
    public String toString() {
        return String.format("[%s] %s - \"%s %s\" %d (%d bytes) | UA: %s",
                timestamp, ip, method, request, statusCode, responseBytes, userAgent);
    }
}