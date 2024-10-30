package com.sascodes.cass.app_gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.*;

@AllArgsConstructor
@Slf4j
public class CASSReactiveJWTDecoder implements ReactiveJwtDecoder {
    private final WebClient webClient;
    private final Environment env;

    public static final Mono<Map<String, Object>> getUserInfo(WebClient webClient, String userInfoEndpoint, String accessToken) {
        try {
            log.info("Fetching user info from endpoint: {}", userInfoEndpoint);
            Mono<Map<String, Object>> res = webClient.get().uri(userInfoEndpoint)
                    .accept(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + accessToken)
                    .exchange()
                    .flatMap(it -> {
                        log.info("Received response with status: {}", it.statusCode().value());
                        if (!it.statusCode().is2xxSuccessful()) {
                            log.error("userInfo request failed with status {}, url {}", it.statusCode().value(), userInfoEndpoint);
                            return it.bodyToMono(String.class)
                                    .mapNotNull(s -> {
                                        log.error("userInfo request failed with body - {}", s);
                                        return Map.<String, Object>of();
                                    });
                        } else {
                            return it.bodyToMono(
                                    new ParameterizedTypeReference<Map<String, Object>>() {
                                    });
                        }
                    })
                    .onErrorMap(RuntimeException.class,
                            mapper -> new InvalidBearerTokenException(
                                    "Invalid token: " + accessToken));
            return res;
        } catch (Exception e) {
            throw new InvalidBearerTokenException("Error while fetching user details, " + e.getMessage());
        }
    }

    private Mono<Map<String, Object>> getUserInfo(String accessToken) {
        log.info("Calling user info endpoint with access token: {}", accessToken);
        return getUserInfo(webClient, this.env.getProperty("cass.user-info.endpoint"), accessToken);
    }

    @SuppressWarnings("unchecked")
    public static List<GrantedAuthority> getAuthorities(Map<String, Object> attributes) {
        log.info("Extracting authorities from attributes: {}", attributes);
        List<GrantedAuthority> gal = new ArrayList<>();
        if (attributes.containsKey("roles")) {
            List<String> roles = (List<String>) attributes.get("roles");
            for (String a : roles) {
                gal.add(new SimpleGrantedAuthority(a));
            }
        }
        return gal;
    }

    @Override
    public Mono<Jwt> decode(String token) throws JwtException {
        log.info("Decoding JWT token: {}", token);
        try {
            ObjectMapper mapper = new ObjectMapper();
            return getUserInfo(token).map(payload -> {
                log.info("Token payload received: {}", payload);
                String[] tokenSpits = token.split("\\.", 0);
                try {
                    Map headers = mapper.readValue(new String(Base64.getDecoder().decode(tokenSpits[0])), Map.class);
                    Map tokenPayload = mapper.readValue(new String(Base64.getDecoder().decode(tokenSpits[1])), Map.class);
                    log.info("Decoded JWT headers: {}", headers);
                    log.info("Decoded JWT payload: {}", tokenPayload);

                    if (tokenPayload.containsKey("typ") && tokenPayload.get("typ").equals("ID")) {
                        var issuerLocation = env.getProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri");
                        if (issuerLocation == null) {
                            throw new IllegalStateException("issuer-uri not specified");
                        }
                        return JwtDecoders.fromIssuerLocation(issuerLocation).decode(token);
                    } else {
                        Instant expiresAt = Instant.ofEpochSecond((int) tokenPayload.get("exp"));
                        Instant issuedAt = Instant.ofEpochSecond((int) tokenPayload.get("iat"));
                        return new Jwt(token, issuedAt, expiresAt, headers, payload);
                    }
                } catch (Exception e) {
                    log.error("Error decoding token: {}", e.getMessage(), e);
                    throw new RuntimeException(e);
                }
            });
        } catch (Exception e) {
            log.error("Error in JWT decoding process: {}", e.getMessage(), e);
            return Mono.empty();
        }
    }

    public static final Optional<Jwt> decodeToken(String token) throws JwtException {
        log.info("Decoding token for static method: {}", token);
        try {
            ObjectMapper mapper = new ObjectMapper();
            String[] tokenSpits = token.split("\\.", 0);
            try {
                Map headers = mapper.readValue(new String(Base64.getDecoder().decode(tokenSpits[0])), Map.class);
                Map tokenPayload = mapper.readValue(new String(Base64.getDecoder().decode(tokenSpits[1])), Map.class);
                Instant expiresAt = tokenPayload.containsKey("exp") ?
                        Instant.ofEpochSecond((int) tokenPayload.get("exp"))
                        : Instant.now();
                Instant issuedAt = Instant.ofEpochSecond((int) tokenPayload.get("iat"));
                return Optional.of(new Jwt(token, issuedAt, expiresAt, headers, tokenPayload));
            } catch (Exception e) {
                log.error("Error in static token decoding: {}", e.getMessage(), e);
                throw new RuntimeException(e);
            }
        } catch (Exception e) {
            log.error("Exception occurred in static decodeToken method: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    public static class CASSAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

        @Override
        public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
            log.info("Converting JWT to authentication token: {}", jwt.getClaims());
            List<GrantedAuthority> authorities = getAuthorities(jwt.getClaims());
            return Mono.just(new JwtAuthenticationToken(jwt, authorities));
        }
    }
}
