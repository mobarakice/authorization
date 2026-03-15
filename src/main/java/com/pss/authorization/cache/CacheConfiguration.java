package com.pss.authorization.cache;

import tools.jackson.databind.cfg.DateTimeFeature;
import com.github.benmanes.caffeine.cache.Caffeine;
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
import org.springframework.data.redis.serializer.GenericJacksonJsonRedisSerializer;
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
        public static final String SUBJECT_ATTRIBUTES = "subject-attributes";
        public static final String SUBJECT_PERMISSIONS = "subject-permissions";
        public static final String PERMISSION_BITMAP = "permission-bitmap";
        public static final String PERMISSION_LOOKUP = "permission-lookup";
        public static final String ROLE_HIERARCHY = "role-hierarchy";
        public static final String POLICIES = "policies";
        public static final String POLICY_BY_TARGET = "policy-by-target";
        public static final String AUTHORIZATION_CONTEXT = "auth-context";
        public static final String ATTRIBUTE_DEFINITIONS = "attribute-definitions";
        public static final String POLICY_APPLICABILITY_BITMAP = "policy-applicability-bitmap";
        public static final String CONTEXT_ROUTING_BITMAP = "context-routing-bitmap";

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
                // GenericJacksonJsonRedisSerializer natively creates a tools.jackson (Jackson
                // 3) JsonMapper
                // We use the builder customizer to add the JavaTimeModule equivalent and
                // disable timestamp dates

                RedisCacheConfiguration defaultConfig = RedisCacheConfiguration.defaultCacheConfig()
                                .prefixCacheNameWith(l2KeyPrefix)
                                .entryTtl(l2Ttl)
                                .serializeKeysWith(RedisSerializationContext.SerializationPair
                                                .fromSerializer(new StringRedisSerializer()))
                                .serializeValuesWith(RedisSerializationContext.SerializationPair
                                                .fromSerializer(GenericJacksonJsonRedisSerializer
                                                                .create(builder -> builder.enableUnsafeDefaultTyping()
                                                                                .customize(mapperBuilder -> mapperBuilder
                                                                                                .findAndAddModules()
                                                                                                .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)))))
                                .disableCachingNullValues();

                // Per-cache TTL configurations
                Map<String, RedisCacheConfiguration> cacheConfigs = new HashMap<>();

                // Permission bitmaps can be cached longer as they're version-controlled
                cacheConfigs.put(PERMISSION_BITMAP, defaultConfig.entryTtl(Duration.ofMinutes(30)));

                // Policies change less frequently
                cacheConfigs.put(POLICIES, defaultConfig.entryTtl(Duration.ofMinutes(15)));

                // Subject roles and attributes may change more frequently
                cacheConfigs.put(SUBJECT_ROLES, defaultConfig.entryTtl(Duration.ofMinutes(5)));
                cacheConfigs.put(SUBJECT_ATTRIBUTES, defaultConfig.entryTtl(Duration.ofMinutes(5)));

                return RedisCacheManager.builder(connectionFactory)
                                .cacheDefaults(defaultConfig)
                                .withInitialCacheConfigurations(cacheConfigs)
                                .enableStatistics()
                                .build();
        }

        private java.util.List<String> getCacheNames() {
                return java.util.List.of(
                                SUBJECT_ROLES,
                                SUBJECT_ATTRIBUTES,
                                SUBJECT_PERMISSIONS,
                                PERMISSION_BITMAP,
                                PERMISSION_LOOKUP,
                                ROLE_HIERARCHY,
                                POLICIES,
                                POLICY_BY_TARGET,
                                AUTHORIZATION_CONTEXT,
                                ATTRIBUTE_DEFINITIONS,
                                POLICY_APPLICABILITY_BITMAP,
                                CONTEXT_ROUTING_BITMAP);
        }
}
