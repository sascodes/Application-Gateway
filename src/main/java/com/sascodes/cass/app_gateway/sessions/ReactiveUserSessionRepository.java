package com.sascodes.cass.app_gateway.sessions;

import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import reactor.core.publisher.Flux;

public interface ReactiveUserSessionRepository<S extends Session> extends ReactiveSessionRepository {
    Flux<S> findByUserId(String userId);
}
