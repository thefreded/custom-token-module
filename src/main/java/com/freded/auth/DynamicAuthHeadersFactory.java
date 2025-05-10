package com.freded.auth;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import org.eclipse.microprofile.rest.client.ext.ClientHeadersFactory;

@RequestScoped
public class DynamicAuthHeadersFactory implements ClientHeadersFactory {

    @Inject
    TokenService tokenService;

    @Context
    HttpHeaders headers;

    @Override
    public MultivaluedMap<String, String> update(MultivaluedMap<String, String> incomingHeaders, MultivaluedMap<String, String> clientOutgoingHeaders) {
        String userToken = headers.getHeaderString("Authorization");
        String token;

        if (userToken != null && userToken.startsWith("Bearer ")) {
            try {
                token = tokenService.exchangeToken(userToken.substring(7));
            } catch (Exception e) {
                throw new RuntimeException("Failed to exchange token ", e);
            }
        } else {
            token = tokenService.getClientAccessToken();
        }

        clientOutgoingHeaders.putSingle("Authorization", "Bearer " + token);
        return clientOutgoingHeaders;
    }
}
