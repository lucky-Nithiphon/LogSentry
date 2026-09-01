import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class LogSanitizer {

    private  static final int MAX_DECODE_ROUNDS = 10; // กำหนดจำนวนรอบสูงสุดในการถอดรหัสเพื่อป้องกัน Loop ไม่สิ้นสุด

    // ฟังก์ชันถอดรหัส URL Encoding (%20, %27, %3C ฯลฯ)
    public static String sanitize(String input) {
       if (input == null || input.isEmpty()){
        return " ";
       }
       
       String current = input;
       int rounds = 0;

       while (rounds < MAX_DECODE_ROUNDS){
          try {
            String decoded = URLDecoder.decode(current, StandardCharsets.UTF_8.name());

            if (decoded.equals(current)){
                break;
            }

            current = decoded;
            rounds ++;
            
          } catch (Exception e) {
            break; // ถ้าเกิด Exception (เช่น รหัสฟอร์แมตผิดพลาด) ให้ใช้ค่าล่าสุดที่ถอดได้
        }
       }
       
       return current;
    }
}
