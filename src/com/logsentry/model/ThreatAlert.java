package com.logsentry.model;

public class ThreatAlert {
    private final String threatType;       // เช่น "SQL Injection (SQLi)"
    private final String mitreId;          // เช่น "T1190"
    private final String mitreTactic;      // เช่น "Initial Access"
    private final String severity;         // "MEDIUM", "HIGH", "CRITICAL"
    private final boolean breachSuspected; // true หาก Payload โจมตีได้รับ HTTP 200 OK

    public ThreatAlert(String threatType, String mitreId, String mitreTactic,
                       String severity, boolean breachSuspected) {
        this.threatType = threatType;
        this.mitreId = mitreId;
        this.mitreTactic = mitreTactic;
        this.severity = severity;
        this.breachSuspected = breachSuspected;
    }

    public String getThreatType() { return threatType; }
    public String getMitreId() { return mitreId; }
    public String getMitreTactic() { return mitreTactic; }
    public String getSeverity() { return severity; }
    public boolean isBreachSuspected() { return breachSuspected; }

    @Override
    public String toString() {
        String breachTag = breachSuspected ? " ⚠️ [POTENTIAL BREACH - HTTP 200]" : " [ATTEMPTED]";
        return String.format("[%s] [%s - %s] %s%s",
                severity, mitreId, mitreTactic, threatType, breachTag);
    }
}