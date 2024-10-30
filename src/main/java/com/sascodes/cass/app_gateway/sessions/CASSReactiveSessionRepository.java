package com.sascodes.cass.app_gateway.sessions;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.session.MapSession;
import org.springframework.session.Session;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;

public class CASSReactiveSessionRepository implements ReactiveUserSessionRepository<MapSession> {
    private Integer defaultMaxInactiveInterval;
    private final Map<String, Session> sessions;

    public CASSReactiveSessionRepository(Map<String, Session> sessions) {
        if (sessions == null) {
            throw new IllegalArgumentException("sessions cannot be null");
        } else {
            this.sessions = sessions;
        }
    }

    public void setDefaultMaxInactiveInterval(int defaultMaxInactiveInterval) {
        this.defaultMaxInactiveInterval = defaultMaxInactiveInterval;
    }

    public Mono<Void> save(MapSession session) {
        return Mono.fromRunnable(() -> {
            if (!session.getId().equals(session.getOriginalId())) {
                this.sessions.remove(session.getOriginalId());
            }

            this.sessions.put(session.getId(), new MapSession(session));
        });
    }

    public Mono<MapSession> findById(String id) {
        return Mono.defer(() -> Mono.justOrEmpty(this.sessions.get(id))
                .filter((session) -> !session.isExpired())
                .map(MapSession::new)
                .switchIfEmpty(this.deleteById(id).then(Mono.empty()))
        );
    }

    public Mono<Void> deleteById(String id) {
        return Mono.fromRunnable(() -> {
            Session var10000 = (Session) this.sessions.remove(id);
        });
    }

    public Mono<MapSession> createSession() {
        return Mono.defer(() -> {
            MapSession result = new MapSession();
            if (this.defaultMaxInactiveInterval != null) {
                result.setMaxInactiveInterval(Duration.ofSeconds((long) this.defaultMaxInactiveInterval));
            }

            return Mono.just(result);
        });
    }

    @Override
    public Mono<Void> save(Session session) {
        return Mono.fromRunnable(() -> {
            if (session instanceof MapSession) {
                if (!session.getId().equals(((MapSession) session).getOriginalId())) {
                    this.sessions.remove(((MapSession) session).getOriginalId());
                }
            }

            this.sessions.put(session.getId(), new MapSession(session));
        });
    }

    public Flux<MapSession> findByUserId(String userId) {
        return Flux.fromStream(sessions.entrySet()
                .stream()
                .filter(e -> {
                    if (!e.getValue().getAttributeNames().contains("SPRING_SECURITY_CONTEXT")) {
                        return false;
                    }
                    var securityContext = ((SecurityContext) e.getValue().getAttribute("SPRING_SECURITY_CONTEXT"));
                    if (securityContext.getAuthentication() == null) {
                        return false;
                    }
                    if (!securityContext.getAuthentication().isAuthenticated()) {
                        return false;
                    }
                    return securityContext.getAuthentication().getName().equals(userId);
                })
                .map(Map.Entry::getValue)
                .map(MapSession::new)
        );
    }
}
