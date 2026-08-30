// เก็บข้อมูล Log ที่ผ่ายการแกะแล้ว 

public class LogEntry {
    //Attributes (คุณลักษณะของข้อมูล)
    private String rawLog;
    private String ip;
    private String request;
    private int statusCode; 
    
    //Constructor (ฟังก์ชันสร้าง Object)
    public LogEntry(String rawLog){
        this.rawLog = rawLog;
        this.ip = extractIp(rawLog);
        this.request = extractRequest(rawLog);
        this.statusCode = extractStatusCode(rawLog);

    }
    // Helper Method: ฟังก์ชันช่วยตัดแกะ IP Address
    private String extractIp(String log){
        // หาตำแหน่งของ "ช่องว่างแรก" ในข้อความ
        int spaceIndex = log.indexOf(" ");
        
        // ถ้าเจอช่องว่าง (spaceIndex ไม่เท่ากับ -1) ให้ตัดคำตั้งแต่ตัวแรก (index 0) จนถึงก่อนช่องว่าง
        if (spaceIndex != -1){
            return  log.substring(0, spaceIndex);
        }
        return "UNKNOWN";
    }
    
    // Helper Method: ฟังก์ชันช่วยตัดแกะ Request Path/URL
    private String extractRequest(String log){
      // หาตำแหน่งอัญประกาศตัวแรก (") และตัวสุดท้าย (") ใน Log
      // หมายเหตุ: \" เป็นการ Escape Character เพื่อบอก Java ว่าเราหมายถึงตัวอักษร " จริงๆ
      int firstQuote = log.indexOf("\"");
      int lastQuote = log.lastIndexOf("\"");
      
      // ถ้าพบอัญประกาศทั้งเปิดและปิด ให้ตัดเอาข้อความระหว่างกลางออกมา
      if (firstQuote != -1 && lastQuote > firstQuote){
        return log.substring(firstQuote + 1, lastQuote);
      }
      return log;
    }
    
    // เพิ่มการหั่นเอา HTTP Status Code (เช่น 200, 404)
    private int extractStatusCode(String log){
        try{
            int lastQuote = log.lastIndexOf("\"");
            if (lastQuote != -1 && lastQuote + 2 < log.length()){
                // ดึงข้อความหลังอัญประกาศปิด แล้วตัดเอาตัวเลข 3 หลัก
                String afterQuote = log.substring(lastQuote + 2) .trim();
                String codeStr = afterQuote.split(" ")[0]; // ตัดข้อมูลส่วนท้ายด้วยช่องว่าง [0] คือตัวแรก
                return  Integer.parseInt(codeStr); //คืนค่า Status Code ที่แปลงเป็นตัวเลขแล้ว
            }
        } catch(Exception e){
            System.out.println("[ERROR] " + e.getMessage());
        } 
        return 0; // คืนค่า 0 ถ้าแกะ Status Code ไม่ได้
    }

    

    public String getRawLog(){
        return  rawLog;
    }
    public String getIp(){
        return ip;
    }
    public String getRequest(){
        return request;
    }
    public int getStatusCode(){
        return statusCode;
    }

}