package com.pss.authorization.cache;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Cache configuration for two-level caching:
 * - L1: Caffeine (in-process, ultra-fast)
 * - L2: Redis (distributed, consistent)
 */
@Configuration
@EnableCaching
public class CacheConfiguration {

        @Value("${authorization.cache.l1.max-size:10000}")
        private int l1MaxSize;

        @Value("${authorization.cache.l1.expire-after-write:5m}")
        private Duration l1ExpireAfterWrite;

        @Value("${authorization.cache.l2.ttl:10m}")
        private Duration l2Ttl;

        @Value("${authorization.cache.l2.key-prefix:authz:}")
        private String l2KeyPrefix;

        // Cache names
        public static final String SUBJECT_ROLES = "subject-roles";
        public static final String SUBJECT_PERMISSIONS = "subject-permissions";
        public static final String PERMISSION_BITMAP = "permission-bitmap";
        public static final String PERMISSION_LOOKUP = "permission-lookup";
        public static final String ROLE_HIERARCHY = "role-hierarchy";
        public static final String POLICIES = "policies";
        public static final String POLICY_BY_TARGET = "policy-by-target";
        public static final String AUTHORIZATION_CONTEXT = "auth-context";
        public static final String ATTRIBUTE_DEFINITIONS = "attribute-definitions";

        /**
         * Primary L1 cache manager using Caffeine for ultra-low latency.
         * Target: < 0.1ms lookup time.
         */
        @Bean
        @Primary
        public CacheManager caffeineCacheManager() {
                CaffeineCacheManager cacheManager = new CaffeineCacheManager();
                cacheManager.setCaffeine(Caffeine.newBuilder()
                                .maximumSize(l1MaxSize)
                                .expireAfterWrite(l1ExpireAfterWrite)
                                .recordStats()); // Enable stats for monitoring
                cacheManager.setCacheNames(getCacheNames());
                return cacheManager;
        }

        /**
         * L2 cache manager using Redis for distributed caching.
         * Target: < 1ms lookup time.
         */
        @Bean
        public RedisCacheManager redisCacheManager(RedisConnectionFactory connectionFactory) {
                // ObjectMapper with JSR310 support for java.time types (Instant, LocalDateTime,
                // etc.)
                ObjectMapper redisMapper = new ObjectMapper();
                redisMapper.registerModule(new JavaTimeModule());
                redisMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
                redisMapper.activateDefaultTyping(
                                redisMapper.getPolymorphicTypeValidator(),
                                ObjectMapper.DefaultTyping.NON_FINAL);

                RedisCacheConfiguration defaultConfig = RedisCacheConfiguration.defaultCacheConfig()
                                .prefixCacheNameWith(l2KeyPrefix)
                                .entryTtl(l2Ttl)
                                .serializeKeysWith(RedisSerializationContext.SerializationPair
                                                .fromSerializer(new StringRedisSerializer()))
                                .serializeValuesWith(RedisSerializationContext.SerializationPair
                                                .fromSerializer(new GenericJackson2JsonRedisSerializer(redisMapper)))
                                .disableCachingNullValues();

                // Per-cache TTL configurations
                Map<String, RedisCacheConfiguration> cacheConfigs = new HashMap<>();

                // Permission bitmaps can be cached longer as they're version-controlled
                cacheConfigs.put(PERMISSION_BITMAP, defaultConfig.entryTtl(Duration.ofMinutes(30)));

                // Policies change less frequently
                cacheConfigs.put(POLICIES, defaultConfig.entryTtl(Duration.ofMinutes(15)));

                // Subject roles may change more frequently
                cacheConfigs.put(SUBJECT_ROLES, defaultConfig.entryTtl(Duration.ofMinutes(5)));

                return RedisCacheManager.builder(connectionFactory)
                                .cacheDefaults(defaultConfig)
                                .withInitialCacheConfigurations(cacheConfigs)
                                .enableStatistics()
                                .build();
        }

        private java.util.List<String> getCacheNames() {
                return java.util.List.of(
                                SUBJECT_ROLES,
                                SUBJECT_PERMISSIONS,
                                PERMISSION_BITMAP,
                                PERMISSION_LOOKUP,
                                ROLE_HIERARCHY,
                                POLICIES,
                                POLICY_BY_TARGET,
                                AUTHORIZATION_CONTEXT,
                                ATTRIBUTE_DEFINITIONS);
        }
}
