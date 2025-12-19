# Используем JDK для запуска
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Копируем готовый JAR
COPY build/libs/*.jar /app/app.jar



# Запуск приложения
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
