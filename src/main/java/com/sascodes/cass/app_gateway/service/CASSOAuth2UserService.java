package com.sascodes.cass.app_gateway.service;

import com.sascodes.cass.app_gateway.config.CASSReactiveJWTDecoder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import reactor.core.publisher.Mono;

import java.util.List;

public class CASSOAuth2UserService implements ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final DefaultReactiveOAuth2UserService delegate;

    public CASSOAuth2UserService() {
        this.delegate = new DefaultReactiveOAuth2UserService();
    }

    @Override
    public Mono<OAuth2User> loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        return this.delegate.loadUser(userRequest)
                .map(oAuth2User -> {
                    List<GrantedAuthority> authorities = CASSReactiveJWTDecoder.getAuthorities(oAuth2User.getAttributes());
                    return new DefaultOAuth2User(authorities, oAuth2User.getAttributes(), userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint()
                            .getUserNameAttributeName());
                });
    }
}
