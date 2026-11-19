FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

# คัดลอกซอร์สโค้ดและคอมไพล์ทั้งหมดภายใน Container
COPY src ./src
RUN mkdir -p out && javac -d out $(find src -name "*.java")

# กำหนดค่าเริ่มต้นให้รันโหมดเฝ้าระวังไฟล์ Log ที่แชร์ผ่าน Volume
ENV JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8"
ENTRYPOINT ["java", "-cp", "out", "com.logsentry.Main"]
CMD ["--tail", "/logs/access.log"]