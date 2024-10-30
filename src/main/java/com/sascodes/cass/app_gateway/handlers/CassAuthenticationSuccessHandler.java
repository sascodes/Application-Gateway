//package com.sascodes.cass.app_gateway.handlers;
//
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.web.server.DefaultServerRedirectStrategy;
//import org.springframework.security.web.server.ServerRedirectStrategy;
//import org.springframework.security.web.server.WebFilterExchange;
//import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
//import reactor.core.publisher.Mono;
//import reactor.core.publisher.MonoSink;
//
//import java.net.URI;
//@Slf4j
//public class CassAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {
//    ServerRedirectStrategy serverRedirectStrategy = new DefaultServerRedirectStrategy();
//    @Override
//    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
//        try {
//            return serverRedirectStrategy.sendRedirect(webFilterExchange.getExchange(), webFilterExchange.getExchange().getRequest().getURI());
//        } catch (Exception e) {
//            log.error("Error in success handler", e);
//            throw new RuntimeException(e);
//        }
//    }
//}
