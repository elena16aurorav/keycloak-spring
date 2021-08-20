package com.example.demo;

import lombok.RequiredArgsConstructor;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {

    private final KeycloakService keycloakService;
    private final KeycloakClientFacade client;

    @GetMapping("/actual-token")
    public String getActualToken() {
        return keycloakService.getActualAccessTokenCache();
    }

    @GetMapping("/public-key-realm")
    public String generateToken() {
        return client.retrieveActivePublicKeyFromPublicRealmEndpoint().getAlgorithm();
    }

    @GetMapping("/verify-token")
    public boolean verifyToken() {
        String token = getActualToken();

        if(null == keycloakService.validateToken(token)){
            return false;
        }
        else{
            return true;
        }
    }




}
