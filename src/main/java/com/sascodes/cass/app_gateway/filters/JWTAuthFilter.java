package com.sascodes.cass.app_gateway.filters;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JWTAuthFilter implements WebFilter {
//    @Override
//    public GatewayFilter apply(Object config) {
//        return (exchange, chain) -> {
//            String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
//
//            exchange.getRequest().mutate()
//                    .header("Authorization", token)
//                    .build();
//            return chain.filter(exchange);
//        };
//    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var token = exchange.getRequest().getCookies().getFirst(HttpHeaders.AUTHORIZATION);

        exchange.getRequest().getHeaders().forEach((name, values) -> {
            values.forEach(value -> log.info("{}: {}", name, value));
        });

        exchange.getRequest().mutate()
                .header("Authorization", token.toString())
                .build();

        return chain.filter(exchange);
    }
}
