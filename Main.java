import java.util.List;

public class Main {
    public static void main(String[] args){
        System.out.println("=================================================");
        System.out.println("   LogSentry v0.1.1 - Blue Team Security Engine  ");
        System.out.println("=================================================\n");
        
        // 1. ระบุตำแหน่งไฟล์ Log จริงในเครื่อง (สมมติชื่อไฟล์ access.log)
        String logFilePath = "access.log";
        // 2. เรียกใช้งาน LogFileReader เพื่ออ่านไฟล์จาก Disk
        LogFileReader fileReader = new LogFileReader();
        List<String> rawLogs = fileReader.readLogFile(logFilePath);
        System.out.println("[+] อ่านไฟล์: " + logFilePath + " (พบทั้งหมด " + rawLogs.size() + " บรรทัด)\n");

        // เรียกเครื่องมือวิเคราะห์ภัยคุกคาม
        ThreatDetector detector = new ThreatDetector();
        BehaviorAnalyzer behaviorAnalyzer = new BehaviorAnalyzer();
        // วนลูปอ่าน Log ทีละบรรทัด
        for (String rawLog : rawLogs) {

            LogEntry log = new LogEntry(rawLog);// แปลงข้อความดิบให้อยู่ในรูปแบบ LogEntry Object
            List<String> threats = detector.analyze(log); // ส่ง LogEntry ไปวิเคราะห์ผ่าน ThreatDetector
            List<String> behavioralThreats = behaviorAnalyzer.analyzeBehavior(log);
            threats.addAll(behavioralThreats);
            // แสดงผลการวิเคราะห์
            System.out.println("[IP]: " + log.getIp() + " | [Status]: " + log.getStatusCode());
            System.out.println("[Request]: " + log.getRequest());

            if(!threats.isEmpty()){
                System.out.println("      \\_______[ALERT] Threats Found: " + threats);
            } else {
                System.out.println("      \\_______[INFO] Status: Clean Traffic");
            }
            System.out.println("-------------------------------------------------");
        }
    }
}