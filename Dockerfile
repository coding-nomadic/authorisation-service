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
COPY --from=build /target/token-service-0.0.1-SNAPSHOT test.jar
# ENV PORT=8080
EXPOSE 9090
ENTRYPOINT ["java","-jar","test.jar"]