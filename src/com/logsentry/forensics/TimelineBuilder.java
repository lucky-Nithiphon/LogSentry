package com.logsentry.forensics;

import com.logsentry.model.LogEntry;
import com.logsentry.model.ThreatAlert;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class TimelineBuilder {

    // เก็บประวัติการโจมตีแยกตาม Source IP (รักษาตามลำดับที่พบ)
    private final Map<String, AttackerProfile> attackerProfiles = new LinkedHashMap<>();

    public synchronized void recordIncident(LogEntry entry, List<ThreatAlert> alerts) {
        if (entry == null || alerts == null || alerts.isEmpty()) {
            return;
        }

        AttackerProfile profile = attackerProfiles.computeIfAbsent(
                entry.getIp(), AttackerProfile::new
        );
        profile.addEvent(entry, alerts);
    }

    public synchronized Map<String, AttackerProfile> getAllProfiles() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(attackerProfiles));
    }

    // แสดงสรุปไทม์ไลน์ผู้โจมตีแต่ละ IP บนหน้าจอ Console
    public synchronized void printConsoleSummary() {
        System.out.println("\n============================================================");
        System.out.println("🕵️  LOG SENTRY — FORENSICS INCIDENT TIMELINE SUMMARY");
        System.out.println("============================================================");

        if (attackerProfiles.isEmpty()) {
            System.out.println("✅ ไม่พบกิจกรรมต้องสงสัยในรอบการทำงานนี้");
            return;
        }

        for (AttackerProfile profile : attackerProfiles.values()) {
            String statusBadge = profile.hasConfirmedBreach()
                    ? "🔴 CONFIRMED/POTENTIAL BREACH (HTTP 200)"
                    : "🟡 ATTEMPTED ATTACKS ONLY";

            System.out.println("\n🎯 Attacker IP : " + profile.getIp() + "  [" + statusBadge + "]");
            System.out.println("   ├─ First Seen  : " + profile.getFirstSeen());
            System.out.println("   ├─ Last Seen   : " + profile.getLastSeen());
            System.out.println("   ├─ Total Alerts: " + profile.getTotalAlertCount() + " alerts (" + profile.getTimeline().size() + " requests)");
            System.out.println("   ├─ User-Agents : " + String.join(", ", profile.getUserAgents()));
            System.out.println("   └─ Attack Timeline:");

            int step = 1;
            for (TimelineEvent event : profile.getTimeline()) {
                System.out.printf("      %d. [%s] %s %s -> HTTP %d (%d bytes)%n",
                        step++,
                        event.getTimestamp(),
                        event.getMethod(),
                        event.getRequest(),
                        event.getStatusCode(),
                        event.getResponseBytes());
                for (String alertText : event.getAlerts()) {
                    System.out.println("         └─ " + alertText);
                }
            }
        }
        System.out.println("============================================================");
    }

    // คลาสเก็บโปรไฟล์และลำดับเหตุการณ์ของคนร้าย 1 IP
    public static class AttackerProfile {
        private final String ip;
        private String firstSeen;
        private String lastSeen;
        private boolean confirmedBreach = false;
        private int totalAlertCount = 0;
        private final Set<String> userAgents = new LinkedHashSet<>();
        private final List<TimelineEvent> timeline = new ArrayList<>();

        public AttackerProfile(String ip) {
            this.ip = ip;
        }

        public void addEvent(LogEntry entry, List<ThreatAlert> alerts) {
            if (firstSeen == null) {
                firstSeen = entry.getTimestamp();
            }
            lastSeen = entry.getTimestamp();
            userAgents.add(entry.getUserAgent());

            List<String> alertDescriptions = new ArrayList<>();
            for (ThreatAlert alert : alerts) {
                String text = alert.toString();
                alertDescriptions.add(text);
                if (text.contains("POTENTIAL BREACH")) {
                    confirmedBreach = true;
                }
            }

            totalAlertCount += alertDescriptions.size();
            timeline.add(new TimelineEvent(
                    entry.getTimestamp(),
                    entry.getMethod(),
                    entry.getRequest(),
                    entry.getStatusCode(),
                    entry.getResponseBytes(),
                    alertDescriptions
            ));
        }

        public String getIp() { return ip; }
        public String getFirstSeen() { return firstSeen; }
        public String getLastSeen() { return lastSeen; }
        public boolean hasConfirmedBreach() { return confirmedBreach; }
        public int getTotalAlertCount() { return totalAlertCount; }
        public Set<String> getUserAgents() { return userAgents; }
        public List<TimelineEvent> getTimeline() { return timeline; }
    }

    // คลาสเก็บรายละเอียดแต่ละก้าวในไทม์ไลน์
    public static class TimelineEvent {
        private final String timestamp;
        private final String method;
        private final String request;
        private final int statusCode;
        private final long responseBytes;
        private final List<String> alerts;

        public TimelineEvent(String timestamp, String method, String request,
                             int statusCode, long responseBytes, List<String> alerts) {
            this.timestamp = timestamp;
            this.method = method;
            this.request = request;
            this.statusCode = statusCode;
            this.responseBytes = responseBytes;
            this.alerts = alerts;
        }

        public String getTimestamp() { return timestamp; }
        public String getMethod() { return method; }
        public String getRequest() { return request; }
        public int getStatusCode() { return statusCode; }
        public long getResponseBytes() { return responseBytes; }
        public List<String> getAlerts() { return alerts; }
    }
}