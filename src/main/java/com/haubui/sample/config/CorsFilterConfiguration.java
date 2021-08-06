package com.haubui.sample.config;

import com.haubui.sample.constant.GatewayConstant;
import com.haubui.sample.security.jwt.TokenProvider;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

@Configuration
public class CorsFilterConfiguration {

    @Autowired
    private Environment env;

    @Bean
    public CorsFilter corsFilter() {
        String allowedOrigins = env.getProperty("app.security.cors.allowed-origins", GatewayConstant.BLANK);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        if (StringUtils.isNotBlank(allowedOrigins)) {
            _log.debug("Registering CORS filter");
            CorsConfiguration corsConfiguration = createCorsConfiguration();
            source.registerCorsConfiguration("/api/**", corsConfiguration);
            source.registerCorsConfiguration("/management/**", corsConfiguration);
            source.registerCorsConfiguration("/v2/api-docs", corsConfiguration);
            source.registerCorsConfiguration("/v3/api-docs", corsConfiguration);
            source.registerCorsConfiguration("/swagger-resources", corsConfiguration);
            source.registerCorsConfiguration("/swagger-ui/**", corsConfiguration);
        }
        return new CorsFilter(source);
    }

    private CorsConfiguration createCorsConfiguration() {

        CorsConfiguration corsConfiguration = new CorsConfiguration();
        String allowedOrigins = env.getProperty("app.security.cors.allowed-origins");
        corsConfiguration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));

        String allowedMethods = env.getProperty("app.security.cors.allowed-methods");
        corsConfiguration.setAllowedMethods(Arrays.asList(allowedMethods.split(",")));

        String allowedHeaders = env.getProperty("app.security.cors.allowed-headers");
        corsConfiguration.setAllowedHeaders(Arrays.asList(allowedHeaders.split(",")));

        String exposedHeaders = env.getProperty("app.security.cors.exposed-headers");
        corsConfiguration.setExposedHeaders(Arrays.asList(exposedHeaders.split(",")));

        Boolean allowCredentials = Boolean.valueOf(env.getProperty("app.security.cors.allow-credentials"));
        corsConfiguration.setAllowCredentials(allowCredentials);

        Long maxAge = Long.valueOf(env.getProperty("app.security.cors.max-age"));
        corsConfiguration.setMaxAge(maxAge);

        return corsConfiguration;
    }

    private static final Logger _log = LoggerFactory.getLogger(TokenProvider.class);
}
