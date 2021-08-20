package com.example.demo;


import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@Configuration
public class CachingConfig {

    @Value("${jwt.lifetime}")
    private int lifetime;

    public static final String KEYCLOAK_TOKENS_CACHE = "keycloak_tokens";
    public static final String KEYCLOAK_PUBLIC_KEYS_CACHE = "keycloak_public_keys";

    @Bean
    public CacheManager cacheManager(Ticker ticker){
        var cacheManager = new SimpleCacheManager();
        cacheManager.setCaches(
                Arrays.asList(
                        buildCache(KEYCLOAK_TOKENS_CACHE, ticker, (lifetime-1)*60),
                        buildCache(KEYCLOAK_PUBLIC_KEYS_CACHE, ticker, (lifetime-1)*60)
                )
        );
        return cacheManager;
    }

    private CaffeineCache buildCache(String name, Ticker ticker, int secondToExpire){
        return new CaffeineCache(name, Caffeine.newBuilder()
                .expireAfterWrite(secondToExpire, TimeUnit.SECONDS)
                .maximumSize(1)
                .ticker(ticker)
                .build());
    }

    @Bean
    public Ticker ticker(){
        return Ticker.systemTicker();
    }
}
