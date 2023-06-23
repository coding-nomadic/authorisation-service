#
# Build stage
#
FROM maven:3.8.2-jdk-11 AS build
COPY . .
RUN mvn clean package -DskipTests

#
# Package stage
#
FROM openjdk:11-jdk-slim
COPY --from=build /target/token-service-0.0.1-SNAPSHOT demo.jar
# ENV PORT=8080
EXPOSE 9090
ENTRYPOINT ["java","-jar","demo.jar"]
