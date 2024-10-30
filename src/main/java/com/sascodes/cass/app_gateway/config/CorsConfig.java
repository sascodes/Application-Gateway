package com.sascodes.cass.app_gateway.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@Configuration
public class CorsConfig implements WebFluxConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:8080") // Allow your auth server
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowCredentials(true) // Allow cookies to be included
                .allowedHeaders("*")
                .maxAge(3600);
    }
}
