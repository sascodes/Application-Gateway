package com.sascodes.cass.app_gateway.filters;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

@Component
public class JWTAuthFilter extends AbstractGatewayFilterFactory {
    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            exchange.getRequest().mutate()
                    .header("X_APP_NAME", "task-service")
                    .build();
            return chain.filter(exchange);
        };
    }
}
