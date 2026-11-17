package com.logsentry.output;

import com.logsentry.forensics.TimelineBuilder;
import com.logsentry.forensics.TimelineBuilder.AttackerProfile;
import com.logsentry.forensics.TimelineBuilder.TimelineEvent;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class JsonReportExporter {

    public void export(TimelineBuilder timelineBuilder, String outputPath) {
        Map<String, AttackerProfile> profiles = timelineBuilder.getAllProfiles();
        String generatedAt = ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        int totalIncidents = 0;
        int breachedIps = 0;
        for (AttackerProfile p : profiles.values()) {
            totalIncidents += p.getTotalAlertCount();
            if (p.hasConfirmedBreach()) {
                breachedIps++;
            }
        }

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"tool\": \"LogSentry Mini-SIEM\",\n");
        json.append("  \"version\": \"v0.7.0\",\n");
        json.append("  \"generated_at\": \"").append(escapeJson(generatedAt)).append("\",\n");
        json.append("  \"summary\": {\n");
        json.append("    \"unique_attacker_ips\": ").append(profiles.size()).append(",\n");
        json.append("    \"ips_with_potential_breach\": ").append(breachedIps).append(",\n");
        json.append("    \"total_alerts_triggered\": ").append(totalIncidents).append("\n");
        json.append("  },\n");
        json.append("  \"attackers\": [\n");

        List<AttackerProfile> profileList = new ArrayList<>(profiles.values());
        for (int i = 0; i < profileList.size(); i++) {
            AttackerProfile p = profileList.get(i);
            json.append("    {\n");
            json.append("      \"source_ip\": \"").append(escapeJson(p.getIp())).append("\",\n");
            json.append("      \"potential_breach\": ").append(p.hasConfirmedBreach()).append(",\n");
            json.append("      \"first_seen\": \"").append(escapeJson(p.getFirstSeen())).append("\",\n");
            json.append("      \"last_seen\": \"").append(escapeJson(p.getLastSeen())).append("\",\n");
            json.append("      \"total_alerts\": ").append(p.getTotalAlertCount()).append(",\n");

            // User-Agents array
            json.append("      \"user_agents\": [");
            List<String> uaList = new ArrayList<>(p.getUserAgents());
            for (int u = 0; u < uaList.size(); u++) {
                json.append("\"").append(escapeJson(uaList.get(u))).append("\"");
                if (u < uaList.size() - 1) json.append(", ");
            }
            json.append("],\n");

            // Timeline array
            json.append("      \"timeline\": [\n");
            List<TimelineEvent> events = p.getTimeline();
            for (int e = 0; e < events.size(); e++) {
                TimelineEvent ev = events.get(e);
                json.append("        {\n");
                json.append("          \"timestamp\": \"").append(escapeJson(ev.getTimestamp())).append("\",\n");
                json.append("          \"method\": \"").append(escapeJson(ev.getMethod())).append("\",\n");
                json.append("          \"request\": \"").append(escapeJson(ev.getRequest())).append("\",\n");
                json.append("          \"status_code\": ").append(ev.getStatusCode()).append(",\n");
                json.append("          \"response_bytes\": ").append(ev.getResponseBytes()).append(",\n");
                json.append("          \"detections\": [");

                List<String> dets = ev.getAlerts();
                for (int d = 0; d < dets.size(); d++) {
                    json.append("\"").append(escapeJson(dets.get(d))).append("\"");
                    if (d < dets.size() - 1) json.append(", ");
                }
                json.append("]\n");
                json.append("        }").append(e < events.size() - 1 ? "," : "").append("\n");
            }
            json.append("      ]\n");
            json.append("    }").append(i < profileList.size() - 1 ? "," : "").append("\n");
        }

        json.append("  ]\n");
        json.append("}\n");

        try {
            Files.write(Paths.get(outputPath), json.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("💾 บันทึกรายงาน Forensics สำเร็จที่ไฟล์: " + outputPath);
        } catch (IOException e) {
            System.err.println("❌ ไม่สามารถบันทึกไฟล์รายงานได้: " + e.getMessage());
        }
    }

    // ป้องกันอักขระพิเศษใน Payload โจมตีทำให้โครงสร้าง JSON เสียหาย
    private String escapeJson(String text) {
        if (text == null) return "";
        return text.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\b", "\\b")
                   .replace("\f", "\\f")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }
}