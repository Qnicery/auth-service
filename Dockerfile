# Используем JDK для запуска
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Копируем готовый JAR
COPY build/libs/*.jar /app/app.jar

# Указываем порт, который слушает сервис
EXPOSE 9090

# Запуск приложения
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
