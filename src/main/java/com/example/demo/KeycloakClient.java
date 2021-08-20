package com.example.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.keycloak.OAuth2Constants;
import org.keycloak.RSATokenVerifier;
import org.keycloak.adapters.HttpClientBuilder;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.KeysMetadataRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static com.example.demo.CachingConfig.KEYCLOAK_TOKENS_CACHE;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeycloakClient {

    @Value("${keycloak-authz-server.user.user1.login}")
    private String userLogin;

    @Value("${keycloak-authz-server.user.user1.password}")
    private String userPassword;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    public static final String CURRENT_TOKENS = "current_tokens";

    public org.keycloak.authorization.client.Configuration getKeyCloakConfig(){
        HttpClient httpClient = new HttpClientBuilder().build();
        Configuration configuration = new Configuration();
        return configuration;
    }

    public Map<String, Object> getCredentials(){
        Map<String, Object> credentials = new HashMap<>();
        if (clientSecret == null) {
            credentials.put("secret", clientSecret);
        }
        else{
            credentials.put("secret", "");
        }
        return credentials;
    }

    /**
     * receive new AccessToken and RefreshToken by username/password
     */
    @Cacheable(value=KEYCLOAK_TOKENS_CACHE, key = "#root.target.CURRENT_TOKENS")
    public AccessTokenResponse getTokenByPasswordCache(){
        log.info("getTokenByPasswordCache");
        String url = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        Http http = new Http(getKeyCloakConfig(), (params, headers) -> {});
        return http.<AccessTokenResponse>post(url)
                .authentication()
                .client()
                .form()
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", clientSecret)
                .param("username", userLogin)
                .param("password", userPassword)
                .response()
                .json(AccessTokenResponse.class)
                .execute();
    }

    /**
     * Receive new AccessToken and RefreshToken by OldRefreshToken
     * @param refreshToken
     */
    public AccessTokenResponse refreshTokenCache(String refreshToken) {
        log.info("refreshTokenCache");
        String url = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        Http http = new Http(getKeyCloakConfig(), (params, headers) -> {});
        return http.<AccessTokenResponse>post(url)
                .authentication()
                .client()
                .form()
                .param("grant_type", "refresh_token")
                .param("refresh_token", refreshToken)
                .param("client_id", clientId)
                .param("client_secret", (String) getCredentials().get("secret"))
                .response()
                .json(AccessTokenResponse.class)
                .execute();
    }

}

