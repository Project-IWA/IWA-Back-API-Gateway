# Utilisez une image de base. Par exemple, pour une application Spring Boot :
FROM openjdk:17

# Mettez en place un répertoire pour votre application
WORKDIR /usr/src/app

# Copiez le fichier JAR de votre application dans l'image Docker
COPY ./target/gateway-0.0.1-SNAPSHOT.jar /usr/src/app

# Commande pour exécuter votre application
CMD ["java", "-jar", "gateway-0.0.1-SNAPSHOT.jar"]
