package com.example.demo;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import static com.example.demo.CachingConfig.KEYCLOAK_TOKENS_CACHE;
import static com.example.demo.DateUtils.convertLocalDateTimeToDate;
import static com.example.demo.KeycloakClient.CURRENT_TOKENS;

@RequiredArgsConstructor
@Service
@Slf4j
public class KeycloakService {

    private final KeycloakClient keyCloakClient;
    private final KeycloakClientFacade keycloakClientFacade;
    private final CacheManager cacheManager;

    public String getActualAccessTokenCache(){
        AccessTokenResponse accessTokenResponse = keyCloakClient.getTokenByPasswordCache();
        if(isExpired(accessTokenResponse.getToken())){//accessToken is not actual
            if(isExpired(accessTokenResponse.getRefreshToken())){//refreshToken is not actual
                log.info("Истекло время жизни refreshToken. Получение токенов по паролю");
                evictCachedToken();
                getActualAccessTokenCache();
            }else{//refreshToken is actual
                log.info("Истекло время жизни accessToken. Получение токенов по refreshToken");
                evictCachedToken();
                accessTokenResponse = keyCloakClient.refreshTokenCache(accessTokenResponse.getRefreshToken());
                var cache = cacheManager.getCache(KEYCLOAK_TOKENS_CACHE);
                cache.put(CURRENT_TOKENS, accessTokenResponse);
            }
        }
        log.info("Текущие значения: accessToken="+accessTokenResponse.getToken()
                +"; refreshToken="+accessTokenResponse.getRefreshToken());
        return accessTokenResponse.getToken();
    }

    public boolean isExpired(String token){
        var decodedJWT = JWT.decode(token);
        return decodedJWT.getExpiresAt().before(convertLocalDateTimeToDate(LocalDateTime.now().minusMinutes(1)));
    }

    private void evictCachedToken(){
        var cache = cacheManager.getCache(KEYCLOAK_TOKENS_CACHE);
        if(null == cache){
            log.error("empty cache");
        }else{
            cache.clear();
        }
    }

    public DecodedJWT validateToken(String token){
        DecodedJWT decodedJWT = JWT.decode(token);
        try {
            TokenVerifier tokenVerifier = TokenVerifier.create(token, AccessToken.class);
            PublicKey publicKey = keycloakClientFacade.retrievePublicKeyFromCertsEndpoint(tokenVerifier.getHeader());

            Algorithm algorithm;
            algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);

            JWTVerifier verifier = JWT.require(algorithm)
                    .build();
            return verifier.verify(decodedJWT);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
