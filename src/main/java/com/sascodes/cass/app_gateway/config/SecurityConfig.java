package com.sascodes.cass.app_gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.sascodes.cass.app_gateway.filters.AuthorizationRedirectionFilter;
import com.sascodes.cass.app_gateway.filters.JWTAuthFilter;
import com.sascodes.cass.app_gateway.handlers.CassAuthenticationFailureHandler;
import com.sascodes.cass.app_gateway.service.CASSOAuth2UserService;
import com.sascodes.cass.app_gateway.sessions.CASSNoOpReactiveSessionRepository;
import com.sascodes.cass.app_gateway.sessions.CASSReactiveSessionRepository;
import com.sascodes.cass.app_gateway.sessions.ReactiveUserSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.session.SessionProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseCookie;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.session.MapSession;
import org.springframework.session.config.annotation.web.server.EnableSpringWebSession;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@EnableSpringWebSession
@RequiredArgsConstructor
public class SecurityConfig {

    //security config
    private final SessionProperties sessionProperties;
    private final Environment env;


    public static MultiValueMap requestParams =  new LinkedMultiValueMap();


    @Autowired
    private ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        return new CASSOAuth2UserService();
    }

    @Bean
    public ClientHttpConnector httpConnector() {
        return new ReactorClientHttpConnector(HttpClient.newConnection());
    }

    @Bean
    public WebClient webClient(ClientHttpConnector clientHttpConnector) {
        return WebClient.builder()
                .clientConnector(clientHttpConnector)
                .build();
    }

    @Bean
    public ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> oauth2AccessTokenResponseClient(WebClient webClient) {
        WebClientReactiveAuthorizationCodeTokenResponseClient client = new WebClientReactiveAuthorizationCodeTokenResponseClient();
        client.setWebClient(webClient);
        return client;
    }


    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder(WebClient webClient, ObjectMapper objectMapper) {
        return new CASSReactiveJWTDecoder(webClient, env);
    }

    @Bean
    public ReactiveUserSessionRepository<MapSession> reactiveSessionRepository() {
        if (env.getProperty("lsac.sessionEnabled", "true").equalsIgnoreCase("true")) {
            CASSReactiveSessionRepository sessionRepository = new CASSReactiveSessionRepository(new ConcurrentHashMap<>());
            int defaultMaxInactiveInterval = 30 * 60;
            if (sessionProperties.getTimeout() != null) {
                defaultMaxInactiveInterval = (int) sessionProperties.getTimeout().toSeconds();
            }
            sessionRepository.setDefaultMaxInactiveInterval(defaultMaxInactiveInterval);
            log.info("Set in-memory session defaultMaxInactiveInterval to {} seconds.", defaultMaxInactiveInterval);
            return sessionRepository;
        } else {
            return new CASSNoOpReactiveSessionRepository();
        }
    }

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http) {

        //By default Spring uses POST, we are changing to Get for now
        var logoutMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/logout");
        var loginMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/login");

        var logoutFilter = new LogoutWebFilter();
        logoutFilter.setRequiresLogoutMatcher(logoutMatcher);
        logoutFilter.setLogoutSuccessHandler(logoutSuccessHandler());

        var urlSecurity = http.authorizeExchange(ex -> ex.pathMatchers(HttpMethod.POST, "/oidc/logout")
                .permitAll()
                .pathMatchers(HttpMethod.GET, "/actuator/health")
                .permitAll()
                .pathMatchers("/notification-service/api/v1/data/count")
                .permitAll());
        if (env.containsProperty("cass.private.urls") && env.getProperty("cass.private.urls") != null) {
            for (String s : Objects.requireNonNull(env.getProperty("cass.private.urls")).split(",")) {
                urlSecurity = urlSecurity.authorizeExchange(ex -> ex.pathMatchers(s.trim()).authenticated());
            }
        }

        if (env.containsProperty("cass.public.urls") && env.getProperty("cass.public.urls") != null) {
            for (String s : Objects.requireNonNull(env.getProperty("cass.public.urls")).split(",")) {
                urlSecurity = urlSecurity.authorizeExchange(ex -> ex.pathMatchers(s.trim()).permitAll());
            }
        }

        var securityFilterChain = urlSecurity;

        if (Boolean.parseBoolean(env.getProperty("cass.resource-server.enabled", "true"))) {
            securityFilterChain = securityFilterChain.oauth2ResourceServer(oauth2 ->
                    oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(new CASSReactiveJWTDecoder.CASSAuthenticationConverter())));
        }

        if (Boolean.parseBoolean(env.getProperty("cass.oauth-login.enabled", "true"))) {
            LoginRedirectorFilter loginRedirectorFilter = new LoginRedirectorFilter(env, loginMatcher);
            securityFilterChain = securityFilterChain.addFilterBefore(loginRedirectorFilter,SecurityWebFiltersOrder.AUTHENTICATION).oauth2Client(Customizer.withDefaults())
                    .oauth2Login(oauth2 -> {
                        oauth2.authorizationRequestResolver(authorizationRequestResolver(this.clientRegistrationRepository))
                                .authenticationSuccessHandler(loginRedirectorFilter.myAuthenticationSuccessHandler())
                                .authenticationFailureHandler(new CassAuthenticationFailureHandler());
                        ;
                    }).addFilterAfter(new AuthorizationRedirectionFilter(), SecurityWebFiltersOrder.AUTHENTICATION);
            securityFilterChain = securityFilterChain.logout(l -> l.requiresLogout(logoutMatcher).logoutSuccessHandler(logoutSuccessHandler()));
            securityFilterChain = securityFilterChain.addFilterBefore(loginRedirectorFilter, SecurityWebFiltersOrder.LOGIN_PAGE_GENERATING)
                    .addFilterBefore(logoutFilter, SecurityWebFiltersOrder.LOGOUT_PAGE_GENERATING);
        }
        securityFilterChain = securityFilterChain.addFilterAfter(new JWTAuthFilter(), SecurityWebFiltersOrder.AUTHORIZATION);
        http.headers(headers ->
                headers.xssProtection(
                        xss -> xss.headerValue(org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter.HeaderValue.ENABLED_MODE_BLOCK)
                ).contentSecurityPolicy(
                        cps -> cps.reportOnly(false)
                ));

        securityFilterChain = securityFilterChain
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable);

        return securityFilterChain.build();
    }
    private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ReactiveClientRegistrationRepository clientRegistrationRepository) {
        DefaultServerOAuth2AuthorizationRequestResolver authorizationRequestResolver =
                new DefaultServerOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository);
        authorizationRequestResolver.setAuthorizationRequestCustomizer(
                authorizationRequestCustomizer());
        return  authorizationRequestResolver;
    }
    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
        return customizer -> customizer
                .additionalParameters(params -> {
                    Object accountname = requestParams.getFirst("accountName");
                    if (!ObjectUtils.isEmpty(accountname)) {
                        params.put("accountName",String.valueOf(accountname));
                        requestParams = new LinkedMultiValueMap();
                    }
                });
    }

    public static class LoginRedirectorFilter implements WebFilter {
        private final Environment env;
        private final ServerWebExchangeMatcher matcher;
        LoginRedirectorFilter(Environment environment, ServerWebExchangeMatcher matcher) {
            this.env = environment;
            this.matcher = matcher;
        }
        public String redirecturlLogin =  "/";
        HashMap redirecturlLoginMap =  new HashMap<String,String>();
        public ServerAuthenticationSuccessHandler myAuthenticationSuccessHandler(){
            return new MySimpleUrlAuthenticationSuccessHandler();
        }
        private class MySimpleUrlAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {
            private DefaultServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();
            @Override
            public Mono<Void> onAuthenticationSuccess(WebFilterExchange exchange, Authentication authentication) {
                try {
                    //Convert to oidc instance to retrieve the token values. you can also get a lot of other fields like claims here
                    var defaultOidcUser = (DefaultOidcUser) authentication.getPrincipal();
                    var tokenValue = defaultOidcUser.getIdToken().getTokenValue();
                    ServerWebExchange serverWebExchange = exchange.getExchange();

                    serverWebExchange.getResponse().addCookie(ResponseCookie.from("Authorization", tokenValue)
                                    .httpOnly(true)
                                    .path("/")
                            .build());


                    //put the mutated serverWebExchange back to webFilterExchange
                    WebFilterExchange webFilterExchange = new WebFilterExchange(serverWebExchange, exchange.getChain());

                    //continue filter chaining
                    return redirectStrategy.sendRedirect(webFilterExchange.getExchange(),new URI(helper(exchange.getExchange())))
                            .doFinally(a->{
                                if(redirecturlLoginMap.containsKey(exchange.getExchange().getRequest().getRemoteAddress().getHostName().toString())){
                                    HashMap<String,String> values = (HashMap<String,String>) redirecturlLoginMap.get(exchange.getExchange().getRequest().getRemoteAddress().getHostName().toString());
                                    if(values.containsKey(exchange.getExchange().getRequest().getId())){
                                        values.remove(exchange.getExchange().getRequest().getId());
                                    }}
                            });
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }
            }
            private String helper(ServerWebExchange exchange){
                var trackingId = exchange.getRequest().getCookies().getFirst("INIT_REQ").getValue();
                if (exchange.getRequest().getPath().toString().equals("/login") & exchange.getRequest().getQueryParams().keySet().contains("error")){
                    return "/";
                }

                if(exchange.getRequest().getCookies().get("SESSION") != null) {
                    var sessionId = exchange.getRequest().getCookies().get("SESSION").stream().filter(session -> session.getName().equals("SESSION")).findFirst();
                    if(sessionId.isEmpty()) {
                        log.error("error when keycloak tries to set a session id");
                        return "/";
                    }
                    if(redirecturlLoginMap.containsKey(sessionId)) {
                        return redirecturlLoginMap.get(sessionId).toString();
                    }
                    else if(redirecturlLoginMap.containsKey(trackingId)) {
                        var path = redirecturlLoginMap.get(trackingId).toString();
                        redirecturlLoginMap.remove(trackingId);
                        redirecturlLoginMap.put(sessionId.get().getValue(), path);
                        return path;
                    }
                }
                return "/";
            }
        }
        @SneakyThrows
        @Override
        public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
            // The login URI for Keycloak
            //URI loginUri = new URI("http://localhost:8083/auth/realms/sascodes/protocol/openid-connect/auth");

            // Capture the current request path
            String requestPath = exchange.getRequest().getPath().toString();

            // Check for the session cookie
            boolean hasSessionCookie = exchange.getRequest().getCookies().get("SESSION") != null &&
                    exchange.getRequest().getCookies().get("SESSION").stream()
                            .anyMatch(cookie -> cookie.getName().equals("SESSION"));

            // If the user is not authenticated and the request is not for login or OAuth authorization
            if (!exchange.getRequest().getPath().toString().equals("/login/oauth2/code/keycloak") && !exchange.getRequest().getPath().toString().equals("/oauth2/authorization/keycloak")) { //TODO do it for authorization endpoint as well /oauth2/authorization/lsac
                // Store the intended request path
                String sessionId = hasSessionCookie ? exchange.getRequest().getCookies().get("SESSION")
                        .stream()
                        .filter(cookie -> cookie.getName().equals("SESSION"))
                        .findFirst()
                        .get()
                        .getValue() : UUID.randomUUID().toString();

                if(!hasSessionCookie) {
                    ResponseCookie cookie = ResponseCookie.from("INIT_REQ", sessionId)
                            .httpOnly(true)
                            .path("/")
                            .build();
                    exchange.getResponse().addCookie(cookie);
                }


                redirecturlLoginMap.put(sessionId, requestPath);

                // Redirect to the Keycloak login page
                //return new DefaultServerRedirectStrategy().sendRedirect(exchange, loginUri).then(Mono.empty());
            }

            // Proceed with the normal filter chain if authenticated or the request is for login
            return chain.filter(exchange);
        }
    }
    @SneakyThrows
    public ServerLogoutSuccessHandler logoutSuccessHandler() {
        return new RedirectServerLogoutSuccessHandler() {
            @Override
            public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
                var logoutQueryParams = exchange.getExchange().getRequest().getQueryParams();
                var redirecturl = logoutQueryParams.getFirst("redirect_uri");
                var appRedirectUrl = env.getProperty("lsac.domainScheme")
                        + "://" + env.getProperty("lsac.domain");
                var redirectLogoutUrl = env.getProperty("lsac.keycloakServer")
                        + "/auth/realms/"
                        + env.getProperty("lsac.keycloakRealm")
                        + "/protocol/openid-connect/logout?redirect_uri=";
                if (!ObjectUtils.isEmpty(redirecturl)) {
                    redirectLogoutUrl = redirectLogoutUrl+URLEncoder.encode(redirecturl, StandardCharsets.UTF_8);
                }else{
                    redirectLogoutUrl = redirectLogoutUrl+ URLEncoder.encode(appRedirectUrl, StandardCharsets.UTF_8);
                }
                try {
                    this.setLogoutSuccessUrl(new URI(redirectLogoutUrl));
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }
                ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();
                try {
                    return redirectStrategy.sendRedirect(exchange.getExchange(),new URI(redirectLogoutUrl) );
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }
    @Bean
    public CorsWebFilter corsFilter() {
        return new CorsWebFilter(corsConfigurationSource());
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration().applyPermitDefaultValues();
        config.setAllowedHeaders(Arrays.asList(HttpHeaders.ORIGIN, HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, HttpHeaders.CONTENT_TYPE, HttpHeaders.ACCEPT, HttpHeaders.AUTHORIZATION, "Origin, Accept", "X-Requested-With", HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpHeaders.CONTENT_DISPOSITION, HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "observe"));
        if(env.containsProperty("lsac.security.originUrls") && env.getProperty("lsac.security.originUrls") != null) {
            var originUrls = env.getProperty("lsac.security.originUrls");
            assert originUrls != null;
            config.setAllowedOrigins(Arrays.asList(originUrls.split(",")));
        } else {
            config.setAllowedOrigins(List.of("*"));
        }
        config.setAllowedMethods(Arrays.asList(RequestMethod.GET.name(), RequestMethod.POST.name(), RequestMethod.DELETE.name(), RequestMethod.PUT.name(), RequestMethod.OPTIONS.name(), RequestMethod.PATCH.name(), RequestMethod.HEAD.name()));
        config.setExposedHeaders(Arrays.asList(HttpHeaders.ORIGIN, HttpHeaders.CONTENT_TYPE, HttpHeaders.ACCEPT, HttpHeaders.AUTHORIZATION, HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.CONTENT_DISPOSITION, "observe"));
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
