# ADIdentity (A minimal JWT layer for AD)

This project enables common secure identity restful operations over an existent Active Directory Server.
 
It implements the JWT ( RFC 7519 ) for token generation with verifying operations.

This project uses Quarkus, the Supersonic Subatomic Java Framework ( https://quarkus.io/ )


## Running the application in dev mode

You can run this application in development mode with the following command:
```
./mvnw quarkus:dev
```
Or if you have an environment with maven 3.6.2+ installed and JDK 11 with the following:
```
./mvn quarkus:dev
```

## Running the application with hot reload (Development only)
```
./mvnw compile quarkus:dev 
```

In this way changes are automatically reloaded

## Packaging and running the application

The application can be packaged using `./mvnw package`.
It produces the `adidentity-<version>-runner.jar` file in the `/target` directory.
Be aware that it’s not an _über-jar_ as the dependencies are copied into the `target/lib` directory.

The application is now runnable using `java -jar target/adidentity-<version>-runner.jar`.

## Creating a native executable

You can create a native executable using: `./mvnw package -Pnative`.

Or, if you don't have GraalVM installed, you can run the native executable build in a container using: `./mvnw package -Pnative -Dquarkus.native.container-build=true`.

You can then execute your native executable with: `./target/adidentity-1.0-SNAPSHOT-runner`

If you want to learn more about building native executables, please consult https://quarkus.io/guides/building-native-image.

## Generate and push docker image

You'll need to have docker installed.

Use the following command to generate a docker image:
```
./mvnw clean package -Dquarkus.container-image.build=true
```

Use following command to generate and push a docker image:
```
./mvnw clean package -Dquarkus.container-image.build=true -Dquarkus.container-image.push=true -Dquarkus.container-image.password=<registrypassword>
```

Or to generate and push a native image:
```
./mvnw clean package -Pnative -Dquarkus.native.container-build=true -Dquarkus.container-image.build=true -Dquarkus.container-image.push=true -Dquarkus.container-image.password=<registrypassword>
```

## Useful commands (Quick Guide)

### Extension listing
```
mvnw quarkus:list-extensions
```

### Extension install (Example installing postgresql driver)
```
mvnw quarkus:add-extension -Dextensions="quarkus-jdbc-postgresl"
```

quarkus-resteasy-jsonb