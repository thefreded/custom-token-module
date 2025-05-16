# Custom Token Module

A utility module that provides dynamic authentication header management for microservice communication.

## Features

- Dynamically manages authentication tokens for service-to-service communication
- Handles token exchange between services
- Integrates with Quarkus REST clients

## Usage

1. Add as a dependency in your service's `pom.xml`

2. Register the dynamic headers factory with your REST client interfaces:

```java
@RegisterClientHeaders(DynamicAuthHeadersFactory.class)
public interface YourServiceClient {
    // Your REST client methods
}