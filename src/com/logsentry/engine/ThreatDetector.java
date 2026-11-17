package com.logsentry.engine;

import com.logsentry.model.LogEntry;
import com.logsentry.model.ThreatAlert;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class ThreatDetector {

    // ==========================================
    // 1. SQL Injection Patterns
    // ==========================================
    private static final Pattern SQLI_TAUTOLOGY = Pattern.compile("\\b(OR|AND)\\b\\s+(['\"]?\\w+['\"]?)\\s*(=|>|<|LIKE)\\s*\\2", Pattern.CASE_INSENSITIVE);
    private static final Pattern SQLI_UNION = Pattern.compile("\\bUNION\\b\\s+(\\bALL\\b\\s+)?\\bSELECT\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern SQLI_TIME_BASED = Pattern.compile("\\b(SLEEP|BENCHMARK|WAITFOR\\s+DELAY|PG_SLEEP)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern SQLI_COMMENTS = Pattern.compile("(--|#|/\\*.*?\\*/)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SQLI_DANGEROUS_CMD = Pattern.compile("\\b(DROP\\s+TABLE|INSERT\\s+INTO|UPDATE\\s+\\w+\\s+SET|DELETE\\s+FROM)\\b", Pattern.CASE_INSENSITIVE);

    // ==========================================
    // 2. Cross-Site Scripting (XSS) Patterns
    // ==========================================
    private static final Pattern XSS_SCRIPT_TAG = Pattern.compile("<\\s*script[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern XSS_EVENT_HANDLERS = Pattern.compile("\\bon[a-zA-Z]+\\s*=", Pattern.CASE_INSENSITIVE);
    private static final Pattern XSS_JAVASCRIPT_URI = Pattern.compile("javascript\\s*:", Pattern.CASE_INSENSITIVE);

    // ==========================================
    // 3. Path Traversal Patterns
    // ==========================================
    private static final Pattern PATH_TRAVERSAL_DOTS = Pattern.compile("(\\.\\.[\\\\/])+");
    private static final Pattern SENSITIVE_FILES = Pattern.compile("(etc/(passwd|shadow|hosts)|\\bwin\\.ini\\b|\\bboot\\.ini\\b|\\bweb\\.config\\b|\\.env)", Pattern.CASE_INSENSITIVE);

    // ==========================================
    // 4. OS Command Injection Patterns
    // ==========================================
    private static final Pattern CMD_INJECTION = Pattern.compile("([;&|`]|&&|\\|\\|)\\s*(cat|ls|dir|type|whoami|id|uname|powershell|cmd|curl|wget|sh|bash)\\b", Pattern.CASE_INSENSITIVE);

    // ==========================================
    // 5. Automated Attack Tool User-Agents
    // ==========================================
    private static final Pattern MALICIOUS_USER_AGENTS = Pattern.compile("(sqlmap|nikto|gobuster|dirbuster|wfuzz|ffuf|nmap|masscan|nuclei|hydra)", Pattern.CASE_INSENSITIVE);

    public List<ThreatAlert> analyze(LogEntry entry) {
        List<ThreatAlert> alerts = new ArrayList<>();

        // ถอดรหัส URL Decoding หลายชั้นผ่าน LogSanitizer ก่อนวิเคราะห์
        String cleanRequest = LogSanitizer.sanitize(entry.getRequest());
        boolean isHttp200 = (entry.getStatusCode() == 200);

        // 1. ตรวจจับ SQL Injection -> MITRE T1190 (Initial Access)
        if (SQLI_TAUTOLOGY.matcher(cleanRequest).find()
                || SQLI_UNION.matcher(cleanRequest).find()
                || SQLI_TIME_BASED.matcher(cleanRequest).find()
                || (SQLI_COMMENTS.matcher(cleanRequest).find() && (cleanRequest.contains("'") || cleanRequest.contains("\"")))
                || SQLI_DANGEROUS_CMD.matcher(cleanRequest).find()) {
            String severity = isHttp200 ? "CRITICAL" : "HIGH";
            alerts.add(new ThreatAlert("SQL Injection (SQLi)", "T1190", "Initial Access", severity, isHttp200));
        }

        // 2. ตรวจจับ Cross-Site Scripting (XSS) -> MITRE T1059.007 (Execution)
        if (XSS_SCRIPT_TAG.matcher(cleanRequest).find()
                || XSS_EVENT_HANDLERS.matcher(cleanRequest).find()
                || XSS_JAVASCRIPT_URI.matcher(cleanRequest).find()) {
            alerts.add(new ThreatAlert("Cross-Site Scripting (XSS)", "T1059.007", "Execution", "HIGH", isHttp200));
        }

        // 3. ตรวจจับ Path Traversal -> MITRE T1083 (Discovery)
        if (PATH_TRAVERSAL_DOTS.matcher(cleanRequest).find() || SENSITIVE_FILES.matcher(cleanRequest).find()) {
            String severity = isHttp200 ? "CRITICAL" : "HIGH";
            alerts.add(new ThreatAlert("Path Traversal / Sensitive File Access", "T1083", "Discovery", severity, isHttp200));
        }

        // 4. ตรวจจับ OS Command Injection -> MITRE T1059 (Execution)
        if (CMD_INJECTION.matcher(cleanRequest).find()) {
            alerts.add(new ThreatAlert("OS Command Injection", "T1059", "Execution", "CRITICAL", isHttp200));
        }

        // 5. ตรวจจับเครื่องมือสแกนอัตโนมัติจาก User-Agent -> MITRE T1595 (Reconnaissance)
        if (MALICIOUS_USER_AGENTS.matcher(entry.getUserAgent()).find()) {
            alerts.add(new ThreatAlert("Automated Recon/Exploit Tool (" + entry.getUserAgent() + ")", "T1595", "Reconnaissance", "MEDIUM", false));
        }

        return alerts;
    }
}