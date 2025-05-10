package com.freded.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.oidc.client.OidcClient;
import io.quarkus.oidc.client.OidcClients;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.Getter;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;


@ApplicationScoped
public class TokenService {

    private final String authServerUrl;
    private final String realm;
    private final String clientId;
    private final String clientSecret;
    private final OidcClient defaultClient;
    private volatile AccessTokenCache clientToken;

    @Inject
    public TokenService(
            @ConfigProperty(name = "quarkus.oidc.auth-server-url") String authServerUrl,
            @ConfigProperty(name = "keycloak.realm") String realm,
            @ConfigProperty(name = "quarkus.oidc.client-id") String clientId,
            @ConfigProperty(name = "quarkus.oidc.credentials.secret") String clientSecret,
            OidcClients oidcClients
    ) {
        this.authServerUrl = authServerUrl;
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.defaultClient = oidcClients.getClient("default-client");
    }

    public synchronized String getClientAccessToken() {
        if (clientToken == null || clientToken.isExpired()) {
            try {
                var tokenResponse = defaultClient.getTokens().await().indefinitely();


                long defaultExpiresIn = 300;
                clientToken = new AccessTokenCache(tokenResponse.getAccessToken(), defaultExpiresIn);

            } catch (Exception e) {
                throw new RuntimeException("Failed to obtain client access token", e);
            }
        }
        return clientToken.getToken();
    }

    public String exchangeToken(String subjectToken) {
        try {
            String tokenEndpoint = authServerUrl + "/protocol/openid-connect/token";

            Map<String, String> params = buildTokenExchangeParams(subjectToken);

            String form = params.entrySet().stream()
                    .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" +
                            URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenEndpoint))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();

            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Token exchange failed: " + response.body());
            }

            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(response.body());
            return json.get("access_token").asText();

        } catch (Exception e) {
            throw new RuntimeException("Token exchange failed", e);
        }
    }

    private Map<String, String> buildTokenExchangeParams(String subjectToken) {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        params.put("subject_token", subjectToken);
        params.put("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        params.put("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");
        params.put("client_id", clientId);
        params.put("client_secret", clientSecret);
        return params;
    }

    @Getter
    static class AccessTokenCache {
        private final String token;
        private final long expiresAt;

        public AccessTokenCache(String token, long expiresInSeconds) {
            this.token = token;
            this.expiresAt = System.currentTimeMillis() + (expiresInSeconds * 1000) - 10_000; // 10s buffer
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }
}