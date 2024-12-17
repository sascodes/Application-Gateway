package com.sascodes.cass.app_gateway.handlers;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import reactor.core.publisher.Mono;

public class CassAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {
    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
        webFilterExchange.getExchange().getRequest().getHeaders()
                .forEach((headerName, headerValues) -> System.out.println(headerName + ": " + headerValues));
        System.out.println("Authentication failed: " + exception.getMessage());
        System.out.println("Session ID: " + webFilterExchange.getExchange().getRequest().getCookies().getFirst("SESSION"));
        System.out.println("Authorization Header: " + webFilterExchange.getExchange().getRequest().getHeaders().getFirst("Authorization"));
        return webFilterExchange.getExchange().getResponse().setComplete();
    }

}
