package com.sascodes.cass.app_gateway.filters;

import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationRedirectionFilter implements WebFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return exchange.getPrincipal()
                .doOnNext(principal -> {
                    if (principal != null) {
                        System.out.println("Authenticated Principal: " + principal.getName());
                    } else {
                        System.out.println("No principal available");
                    }
                })
                .then(chain.filter(exchange)); //TODO Check roles and forward accordingly
    }
}
