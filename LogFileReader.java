import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class LogFileReader {

    // ฟังก์ชันรับ Path ของไฟล์ Log แล้วอ่านคืนค่ากลับมาเป็น List ของข้อความบรรทัด Log
    public List<String> readLogFile (String filePath){
        List<String> logLines = new ArrayList<>();
         
        // ใช้ try-with-resources เพื่อให้ Java ปิดไฟล์ให้อัตโนมัติเมื่ออ่านเสร็จ
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))){
            String line;
          
            while ((line = reader.readLine()) != null){
                // ข้ามบรรทัดว่าง
                if(!line.trim().isEmpty()){
                    logLines.add(line);
                }
            }
        }
        catch(IOException e){
            System.out.println("[ERROR] ไม่สามารถอ่านไฟล์ได้: " + e.getMessage());
        }

        return logLines;
    }
}
