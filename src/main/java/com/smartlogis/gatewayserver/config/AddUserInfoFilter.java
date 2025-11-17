package com.smartlogis.gatewayserver.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class AddUserInfoFilter implements GlobalFilter, Ordered {

    private static final String HEADER_USER_ID = "X-User-Id";
    private static final String HEADER_USER_NAME = "X-User-Name";
    private static final String HEADER_ROLES = "X-User-Role";

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx == null ? null : ctx.getAuthentication())
                .flatMap(auth -> {
                    if (!(auth instanceof JwtAuthenticationToken)) {
                        // 인증이 없거나 Jwt가 아니면 그냥 통과
                        return chain.filter(exchange);
                    }

                    JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) auth;
                    Jwt jwt = jwtAuth.getToken();

                    List<String> roles = extractRoles(jwt);
                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header(HEADER_USER_ID, jwt.getSubject() != null ? jwt.getSubject() : "")
                            .header(HEADER_USER_NAME, jwt.getClaimAsString("preferred_username") != null ? jwt.getClaimAsString("preferred_username") : "")
                            .header(HEADER_ROLES, roles.stream().filter(s -> s.startsWith("ROLE")).collect(Collectors.joining(",")))
                            .build();

                    ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

                    return chain.filter(mutatedExchange);
                })
                .switchIfEmpty(chain.filter(exchange))
                .onErrorResume(ex -> {
                    return chain.filter(exchange);
                });
    }

    private List<String> extractRoles(Jwt jwt) {
        List<String> result = new ArrayList<>();
        if (jwt.hasClaim("roles")) {
            Object v = jwt.getClaim("roles");
            if (v instanceof Collection) {
                ((Collection<?>) v).forEach(r -> result.add(r.toString()));
            }
        } else if (jwt.hasClaim("realm_access")) {
            Map<String,Object> realmAccess = jwt.getClaim("realm_access");
            Object r = realmAccess.get("roles");
            if (r instanceof Collection) {
                ((Collection<?>) r).forEach(role -> result.add(role.toString()));
            }
        } else if (jwt.hasClaim("resource_access")) {
            Map<String,Object> resourceAccess = jwt.getClaim("resource_access");
            resourceAccess.values().forEach(v -> {
                if (v instanceof Map) {
                    Object rr = ((Map<?,?>)v).get("roles");
                    if (rr instanceof Collection) {
                        ((Collection<?>) rr).forEach(role -> result.add(role.toString()));
                    }
                }
            });
        }
        return result;
    }
}
