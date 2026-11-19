package com.logsentry;

import com.logsentry.engine.BehaviorAnalyzer;
import com.logsentry.engine.EntropyAnalyzer;
import com.logsentry.engine.ThreatDetector;
import com.logsentry.forensics.TimelineBuilder;
import com.logsentry.model.LogEntry;
import com.logsentry.model.ThreatAlert;
import com.logsentry.output.JsonReportExporter;
import com.logsentry.parser.CommonLogParser;
import com.logsentry.parser.JsonLogParser;
import com.logsentry.parser.LogFileReader;
import com.logsentry.parser.LogParser;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

public class Main {
    private static final String DEFAULT_LOG_PATH = "mock_server/access.log";
    private static final String DEFAULT_REPORT_PATH = "report.json";

    public static void main(String[] args) {
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(System.err, true, StandardCharsets.UTF_8));

        if (args.length == 0) {
            runInteractiveMenu();
            return;
        }

        String command = args[0].trim();
        switch (command) {
            case "--help":
            case "-h":
                printHelp();
                break;
            case "--tail":
                String tailFile = (args.length >= 2) ? args[1] : DEFAULT_LOG_PATH;
                runTailMode(tailFile, DEFAULT_REPORT_PATH);
                break;
            case "--scan":
                String scanFile = (args.length >= 2) ? args[1] : DEFAULT_LOG_PATH;
                runScanMode(scanFile, DEFAULT_REPORT_PATH);
                break;
            case "--investigate":
                if (args.length < 2) {
                    System.err.println("❌ กรุณาระบุ IP เป้าหมาย เช่น: java -cp out com.logsentry.Main --investigate 127.0.0.1");
                    return;
                }
                String targetIp = args[1];
                String invFile = (args.length >= 3) ? args[2] : DEFAULT_LOG_PATH;
                runInvestigateMode(targetIp, invFile, DEFAULT_REPORT_PATH);
                break;
            default:
                runTailMode(command, DEFAULT_REPORT_PATH);
                break;
        }
    }

    private static void runInteractiveMenu() {
        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);

        while (true) {
            System.out.println("\n============================================================");
            System.out.println("🛡️  LogSentry v1.1.0 — Out-of-Band Mini-SIEM & Forensics");
            System.out.println("============================================================");
            System.out.println("   [1] 📡 Real-time Monitor  (เฝ้าดูไฟล์ Log แบบสด)");
            System.out.println("   [2] 🔍 Batch Audit Scan   (สแกนไฟล์ Log ย้อนหลังทั้งไฟล์)");
            System.out.println("   [3] 🎯 Investigate IP     (แกะรอยไทม์ไลน์ทั้งหมดของ IP เป้าหมาย)");
            System.out.println("   [4] 📖 Help               (ดูคู่มือคำสั่ง CLI)");
            System.out.println("   [0] ❌ Exit               (ออกจากโปรแกรม)");
            System.out.println("============================================================");
            System.out.print("👉 เลือกเมนู (0-4): ");

            if (!scanner.hasNextLine()) {
                break;
            }
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    String tailPath = promptLogPath(scanner);
                    runTailMode(tailPath, DEFAULT_REPORT_PATH);
                    return;
                case "2":
                    String scanPath = promptLogPath(scanner);
                    runScanMode(scanPath, DEFAULT_REPORT_PATH);
                    break;
                case "3":
                    System.out.print("🎯 ระบุ IP ผู้โจมตีที่ต้องการแกะรอย (เช่น 127.0.0.1): ");
                    String targetIp = scanner.nextLine().trim();
                    if (targetIp.isEmpty()) {
                        System.out.println("⚠️ กรุณาระบุ IP Address");
                        break;
                    }
                    String invPath = promptLogPath(scanner);
                    runInvestigateMode(targetIp, invPath, DEFAULT_REPORT_PATH);
                    break;
                case "4":
                    printHelp();
                    break;
                case "0":
                    System.out.println("👋 ปิดการทำงาน LogSentry เรียบร้อยครับ");
                    return;
                default:
                    System.out.println("⚠️ กรุณาเลือกหมายเลข 0 ถึง 4 เท่านั้น");
            }
        }
    }

    private static String promptLogPath(Scanner scanner) {
        System.out.print("📂 ระบุไฟล์ Log (กด Enter เพื่อใช้ค่าเริ่มต้น [" + DEFAULT_LOG_PATH + "]): ");
        String input = scanner.nextLine().trim();
        return input.isEmpty() ? DEFAULT_LOG_PATH : input;
    }

    private static void printHelp() {
        System.out.println("\n============================================================");
        System.out.println("📖 LogSentry CLI Usage Guide");
        System.out.println("============================================================");
        System.out.println("  java -cp out com.logsentry.Main");
        System.out.println("      เปิดหน้าเมนูโต้ตอบ (Interactive CLI Menu)\n");
        System.out.println("  java -cp out com.logsentry.Main --tail [logfile]");
        System.out.println("      เฝ้าดูไฟล์ Log แบบ Real-time (กด Ctrl+C เพื่อออกรายงาน)\n");
        System.out.println("  java -cp out com.logsentry.Main --scan [logfile]");
        System.out.println("      สแกนไฟล์ Log ย้อนหลังทั้งหมดและส่งออก report.json ทันที\n");
        System.out.println("  java -cp out com.logsentry.Main --investigate <IP> [logfile]");
        System.out.println("      แกะรอยคำขอทั้งหมด (ทั้งปกติและโจมตี) ของ IP เป้าหมายตามลำดับเวลา\n");
        System.out.println("  java -cp out com.logsentry.Main --help");
        System.out.println("      แสดงหน้าคู่มือนี้");
        System.out.println("============================================================");
    }

    private static void runTailMode(String logFilePath, String reportOutputPath) {
        LogParser commonParser = new CommonLogParser();
        LogParser jsonParser = new JsonLogParser();
        ThreatDetector detector = new ThreatDetector();
        EntropyAnalyzer entropyAnalyzer = new EntropyAnalyzer();
        BehaviorAnalyzer behaviorAnalyzer = new BehaviorAnalyzer();
        TimelineBuilder timelineBuilder = new TimelineBuilder();
        JsonReportExporter reportExporter = new JsonReportExporter();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            timelineBuilder.printConsoleSummary();
            reportExporter.export(timelineBuilder, reportOutputPath);
        }));

        System.out.println("\n============================================================");
        System.out.println("📡 LogSentry — REAL-TIME MONITOR (--tail)");
        System.out.println("📂 Monitoring : " + logFilePath);
        System.out.println("💡 กด Ctrl+C เพื่อหยุดการทำงานและสร้างรายงาน " + reportOutputPath);
        System.out.println("============================================================");

        LogFileReader reader = new LogFileReader();
        reader.startTailing(logFilePath, line ->
                processLogLine(line, commonParser, jsonParser, detector, entropyAnalyzer, behaviorAnalyzer, timelineBuilder, true)
        );
    }

    private static void runScanMode(String logFilePath, String reportOutputPath) {
        Path path = Paths.get(logFilePath);
        if (!Files.exists(path)) {
            System.err.println("❌ ไม่พบไฟล์ Log: " + logFilePath);
            return;
        }

        LogParser commonParser = new CommonLogParser();
        LogParser jsonParser = new JsonLogParser();
        ThreatDetector detector = new ThreatDetector();
        EntropyAnalyzer entropyAnalyzer = new EntropyAnalyzer();
        BehaviorAnalyzer behaviorAnalyzer = new BehaviorAnalyzer();
        TimelineBuilder timelineBuilder = new TimelineBuilder();
        JsonReportExporter reportExporter = new JsonReportExporter();

        System.out.println("\n============================================================");
        System.out.println("🔍 LogSentry — BATCH AUDIT SCAN (--scan)");
        System.out.println("📂 Target Log : " + logFilePath);
        System.out.println("============================================================");

        try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                processLogLine(line, commonParser, jsonParser, detector, entropyAnalyzer, behaviorAnalyzer, timelineBuilder, true);
            }
        } catch (IOException e) {
            System.err.println("❌ เกิดข้อผิดพลาดในการอ่านไฟล์: " + e.getMessage());
            return;
        }

        timelineBuilder.printConsoleSummary();
        reportExporter.export(timelineBuilder, reportOutputPath);
    }

    private static void runInvestigateMode(String targetIp, String logFilePath, String reportOutputPath) {
        Path path = Paths.get(logFilePath);
        if (!Files.exists(path)) {
            System.err.println("❌ ไม่พบไฟล์ Log: " + logFilePath);
            return;
        }

        LogParser commonParser = new CommonLogParser();
        LogParser jsonParser = new JsonLogParser();
        ThreatDetector detector = new ThreatDetector();
        EntropyAnalyzer entropyAnalyzer = new EntropyAnalyzer();
        BehaviorAnalyzer behaviorAnalyzer = new BehaviorAnalyzer();
        TimelineBuilder timelineBuilder = new TimelineBuilder();
        JsonReportExporter reportExporter = new JsonReportExporter();

        List<String> killChainLogs = new ArrayList<>();
        Set<String> userAgents = new LinkedHashSet<>();
        int totalRequests = 0;
        int totalAlerts = 0;
        boolean breachDetected = false;

        try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                LogEntry entry = parseAuto(line, commonParser, jsonParser);
                if (entry == null) {
                    continue;
                }

                List<ThreatAlert> alerts = analyzeEntry(entry, detector, entropyAnalyzer, behaviorAnalyzer);

                if (targetIp.equals(entry.getIp())) {
                    totalRequests++;
                    userAgents.add(entry.getUserAgent());

                    if (!alerts.isEmpty()) {
                        timelineBuilder.recordIncident(entry, alerts);
                        totalAlerts += alerts.size();
                        StringBuilder step = new StringBuilder();
                        step.append(String.format("   %d. 🚨 [%s] %s %s -> HTTP %d (%d bytes)%n",
                                totalRequests, entry.getTimestamp(), entry.getMethod(), entry.getRequest(),
                                entry.getStatusCode(), entry.getResponseBytes()));
                        for (ThreatAlert alert : alerts) {
                            String text = alert.toString();
                            if (text.contains("POTENTIAL BREACH")) {
                                breachDetected = true;
                            }
                            step.append("         └─ ").append(text).append("\n");
                        }
                        killChainLogs.add(step.toString().stripTrailing());
                    } else {
                        killChainLogs.add(String.format("   %d. ⚪ [%s] %s %s -> HTTP %d (%d bytes) [CLEAN]",
                                totalRequests, entry.getTimestamp(), entry.getMethod(), entry.getRequest(),
                                entry.getStatusCode(), entry.getResponseBytes()));
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("❌ เกิดข้อผิดพลาดในการอ่านไฟล์: " + e.getMessage());
            return;
        }

        System.out.println("\n============================================================");
        System.out.println("🎯 FORENSICS IP INVESTIGATION REPORT : " + targetIp);
        System.out.println("============================================================");
        if (totalRequests == 0) {
            System.out.println("ℹ️ ไม่พบประวัติการใช้งานของ IP " + targetIp + " ในไฟล์ " + logFilePath);
            return;
        }

        String status = breachDetected
                ? "🔴 POTENTIAL BREACH DETECTED (HTTP 200)"
                : (totalAlerts > 0 ? "🟡 SUSPICIOUS / ATTEMPTED ATTACKS" : "🟢 CLEAN TRAFFIC ONLY");

        System.out.println("   ├─ Status         : " + status);
        System.out.println("   ├─ Total Requests : " + totalRequests + " requests");
        System.out.println("   ├─ Total Alerts   : " + totalAlerts + " alerts");
        System.out.println("   ├─ User-Agents    : " + String.join(", ", userAgents));
        System.out.println("   └─ Full Kill Chain Timeline (เรียงตามลำดับเหตุการณ์จริง):");
        for (String eventLine : killChainLogs) {
            System.out.println(eventLine);
        }
        System.out.println("============================================================");

        if (totalAlerts > 0) {
            reportExporter.export(timelineBuilder, reportOutputPath);
        }
    }

    private static LogEntry parseAuto(String line, LogParser commonParser, LogParser jsonParser) {
        if (line == null) {
            return null;
        }
        String cleanLine = line.replace("\uFEFF", "").trim();
        if (cleanLine.isEmpty()) {
            return null;
        }
        return cleanLine.startsWith("{") ? jsonParser.parse(cleanLine) : commonParser.parse(cleanLine);
    }

    private static List<ThreatAlert> analyzeEntry(
            LogEntry entry,
            ThreatDetector detector,
            EntropyAnalyzer entropyAnalyzer,
            BehaviorAnalyzer behaviorAnalyzer) {
        List<ThreatAlert> allAlerts = new ArrayList<>(detector.analyze(entry));
        ThreatAlert entropyAlert = entropyAnalyzer.analyze(entry);
        if (entropyAlert != null) {
            allAlerts.add(entropyAlert);
        }
        allAlerts.addAll(behaviorAnalyzer.analyzeBehavior(entry));
        return allAlerts;
    }

    private static void processLogLine(
            String line,
            LogParser commonParser,
            LogParser jsonParser,
            ThreatDetector detector,
            EntropyAnalyzer entropyAnalyzer,
            BehaviorAnalyzer behaviorAnalyzer,
            TimelineBuilder timelineBuilder,
            boolean printRealtimeAlert) {

        LogEntry entry = parseAuto(line, commonParser, jsonParser);
        if (entry == null) {
            return;
        }

        List<ThreatAlert> signatureAlerts = detector.analyze(entry);
        ThreatAlert entropyAlert = entropyAnalyzer.analyze(entry);
        List<ThreatAlert> behaviorAlerts = behaviorAnalyzer.analyzeBehavior(entry);

        List<ThreatAlert> allAlerts = new ArrayList<>(signatureAlerts);
        if (entropyAlert != null) {
            allAlerts.add(entropyAlert);
        }
        allAlerts.addAll(behaviorAlerts);

        if (!allAlerts.isEmpty()) {
            timelineBuilder.recordIncident(entry, allAlerts);

            if (printRealtimeAlert) {
                System.out.println("\n🚨 [SECURITY ALERT] ตรวจพบกิจกรรมน่าสงสัย!");
                System.out.println("   ├─ Source IP  : " + entry.getIp());
                System.out.println("   ├─ Timestamp  : " + entry.getTimestamp());
                System.out.println("   ├─ Request    : " + entry.getMethod() + " " + entry.getRequest());
                System.out.println("   ├─ Response   : HTTP " + entry.getStatusCode() + " (" + entry.getResponseBytes() + " bytes)");
                System.out.println("   └─ Source/UA  : " + entry.getUserAgent());

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
        }
    }
}