package com.logsentry;

import com.logsentry.engine.BehaviorAnalyzer;
import com.logsentry.engine.EntropyAnalyzer;
import com.logsentry.engine.ThreatDetector;
import com.logsentry.forensics.TimelineBuilder;
import com.logsentry.model.LogEntry;
import com.logsentry.model.ThreatAlert;
import com.logsentry.output.JsonReportExporter;
import com.logsentry.parser.CommonLogParser;
import com.logsentry.parser.LogFileReader;
import com.logsentry.parser.LogParser;
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        String logFilePath = "mock_server/access.log";
        String reportOutputPath = "report.json";

        LogFileReader reader = new LogFileReader();
        LogParser parser = new CommonLogParser();
        ThreatDetector detector = new ThreatDetector();
        EntropyAnalyzer entropyAnalyzer = new EntropyAnalyzer();
        BehaviorAnalyzer behaviorAnalyzer = new BehaviorAnalyzer();

        TimelineBuilder timelineBuilder = new TimelineBuilder();
        JsonReportExporter reportExporter = new JsonReportExporter();

        // เมื่อกด Ctrl+C หยุดโปรแกรม ให้สรุปไทม์ไลน์และส่งออกไฟล์ report.json อัตโนมัติ
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            timelineBuilder.printConsoleSummary();
            reportExporter.export(timelineBuilder, reportOutputPath);
        }));

        System.out.println("============================================================");
        System.out.println("🛡️  LogSentry v0.7.0 (Phase 3: Forensics Timeline & JSON Report)");
        System.out.println("📂 Monitoring : " + logFilePath);
        System.out.println("💡 กด Ctrl+C เพื่อหยุดการทำงานและสร้างรายงาน " + reportOutputPath);
        System.out.println("============================================================");

        reader.startTailing(logFilePath, line -> {
            LogEntry entry = parser.parse(line);
            if (entry == null) {
                return;
            }

            List<ThreatAlert> signatureAlerts = detector.analyze(entry);
            ThreatAlert entropyAlert = entropyAnalyzer.analyze(entry);
            List<ThreatAlert> behaviorAlerts = behaviorAnalyzer.analyzeBehavior(entry);

            // รวมการแจ้งเตือนทั้งหมดของบรรทัดนี้
            List<ThreatAlert> allAlerts = new ArrayList<>(signatureAlerts);
            if (entropyAlert != null) {
                allAlerts.add(entropyAlert);
            }
            allAlerts.addAll(behaviorAlerts);

            if (!allAlerts.isEmpty()) {
                // บันทึกลงไทม์ไลน์สำหรับวิเคราะห์ Forensics
                timelineBuilder.recordIncident(entry, allAlerts);

                System.out.println("\n🚨 [SECURITY ALERT] ตรวจพบกิจกรรมน่าสงสัย!");
                System.out.println("   ├─ Source IP  : " + entry.getIp());
                System.out.println("   ├─ Timestamp  : " + entry.getTimestamp());
                System.out.println("   ├─ Request    : " + entry.getMethod() + " " + entry.getRequest());
                System.out.println("   ├─ Response   : HTTP " + entry.getStatusCode() + " (" + entry.getResponseBytes() + " bytes)");
                System.out.println("   └─ User-Agent : " + entry.getUserAgent());

                for (ThreatAlert alert : signatureAlerts) {
                    System.out.println("      🔥 Signature : " + alert);
                }
                if (entropyAlert != null) {
                    System.out.println("      🧬 Entropy   : " + entropyAlert);
                }
                for (ThreatAlert bAlert : behaviorAlerts) {
                    System.out.println("      📊 Behavior  : " + bAlert);
                }
            }
        });
    }
}