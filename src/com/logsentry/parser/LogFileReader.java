package com.logsentry.parser;

import com.logsentry.model.LogEntry;
import  java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class LogFileReader{
    // Functional Interface เป็นตัวส่งต่อข้อความ (Callback) ไปยัง Main
    public interface LogListener {
        void onNewLogLine(String logLine);
    }

    //เมธอดอ่าน Log แบบ Real-time (ทำงานตลอดเวลาคล้าย tail -f ใน Linux)
    public void startTailing(String filePath, LogListener listener){

        //ใช้ FileReader + BufferedReader เปิดอ่านไฟล์ค้างไว้
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {

            //อ่านบรรทัดเก่าที่มีอยู่เดิมในไฟล์ทั้งหมดออกมาก่อน (ถ้ามี)
            String line;
            while ((line = reader.readLine()) != null){
                listener.onNewLogLine(line);
            }

            // เข้าสู่ Infinite Loop เพื่อเฝ้าดูบรรทัดใหม่ที่จะถูกเขียนเข้ามาเพิ่มในอนาคต
            while(true){
                line = reader.readLine();
                if (line != null){ //มีบรรทัดใหม่ถูกเขียนเพิ่มเข้ามา -> ส่งไปประมวลผลทันที
                    listener.onNewLogLine(line);
                }
                else{ // ถ้ายังไม่มีบรรทัดใหม่ -> พัก Thread 500ms (0.5 วินาที) เพื่อประหยัด CPU
                    Thread.sleep(500);
                }
            }
        } catch(IOException e){
            System.err.println("[-] เกิดข้อผิดพลาดในการอ่านไฟล์ Log: " + e.getMessage());
        } catch (InterruptedException e) {
            System.out.println("[!] ปิดระบบเฝ้าระวัง LogSentry");
            Thread.currentThread().interrupt();
        }
    }

}