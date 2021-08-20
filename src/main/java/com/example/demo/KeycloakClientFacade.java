package com.example.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.keycloak.RSATokenVerifier;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static com.example.demo.CachingConfig.KEYCLOAK_PUBLIC_KEYS_CACHE;
import static com.example.demo.CachingConfig.KEYCLOAK_TOKENS_CACHE;

@RequiredArgsConstructor
@Component
public class KeycloakClientFacade {

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

    public String extractAccessTokenFrom(String token) {
        if (token == null) {
            return null;
        }

        try {
            TokenVerifier verifier = TokenVerifier.create(token, AccessToken.class);
            PublicKey publicKey = retrievePublicKeyFromCertsEndpoint(verifier.getHeader());
            return verifier.publicKey(publicKey).verify().getToken().toString();
        } catch (VerificationException e) {
            return null;
        }
    }

    @Cacheable(value=KEYCLOAK_PUBLIC_KEYS_CACHE)
    public List<Map<String, Object>> getPublicKeys(){
        ObjectMapper om = new ObjectMapper();
        String realmCertsUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/certs";
        Map<String, Object> certInfos = null;
        try {
            certInfos = om.readValue(new URL(realmCertsUrl).openStream(), Map.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return (List<Map<String, Object>>) certInfos.get("keys");
    }

    public PublicKey retrievePublicKeyFromCertsEndpoint(JWSHeader jwsHeader) {
        try {
            List<Map<String, Object>> keys = getPublicKeys();

            Map<String, Object> keyInfo = null;
            for (Map<String, Object> key : keys) {
                String kid = (String) key.get("kid");

                if (jwsHeader.getKeyId().equals(kid)) {
                    keyInfo = key;
                    break;
                }
            }

            if (keyInfo == null) {
                return null;
            }

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            String modulusBase64 = (String) keyInfo.get("n");
            String exponentBase64 = (String) keyInfo.get("e");

            Base64.Decoder urlDecoder = Base64.getUrlDecoder();
            BigInteger modulus = new BigInteger(1, urlDecoder.decode(modulusBase64));
            BigInteger publicExponent = new BigInteger(1, urlDecoder.decode(exponentBase64));

            return keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public PublicKey retrieveActivePublicKeyFromPublicRealmEndpoint() {
        try {
            String realmUrl = authServerUrl + "/realms/" + realm;
            ObjectMapper om = new ObjectMapper();
            Map<String, Object> realmInfo = om.readValue(new URL(realmUrl).openStream(), Map.class);
            return toPublicKey((String) realmInfo.get("public_key"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public PublicKey toPublicKey(String publicKeyString) {
        try {
            byte[] publicBytes = Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return null;
        }
    }
}
