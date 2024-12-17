package com.sascodes.cass.app_gateway.sessions;

import org.springframework.session.MapSession;
import org.springframework.session.Session;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public class CASSNoOpReactiveSessionRepository implements ReactiveUserSessionRepository<MapSession> {

    public CASSNoOpReactiveSessionRepository() {
    }

    public Mono<Void> save(MapSession session) {
        return Mono.empty();
    }

    @Override
    public Flux<MapSession> findByUserId(String userId) {
        return Flux.empty();
    }

    @Override
    public Mono createSession() {
        return Mono.empty();
    }

    @Override
    public Mono<Void> save(Session session) {
        return Mono.empty();
    }

    @Override
    public Mono findById(String s) {
        return Mono.empty();
    }

    @Override
    public Mono<Void> deleteById(String s) {
        return Mono.empty();
    }
}
