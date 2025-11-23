package com.smartlogis.gatewayserver.security;

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
public class JwtUserHeaderFilter implements GlobalFilter, Ordered {

    private static final String HEADER_USER_ID = "X-User-Id";
    private static final String HEADER_USER_NAME = "X-User-Name";

	@Override
	public int getOrder() {
		return 4;
	}

	@Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext == null ? null : securityContext.getAuthentication())
                .flatMap(auth -> {
					Jwt jwt = ((JwtAuthenticationToken) auth).getToken();

                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header(HEADER_USER_ID, jwt.getSubject() != null ? jwt.getSubject() : "")
                            .header(HEADER_USER_NAME, jwt.getClaimAsString("preferred_username") != null ? jwt.getClaimAsString("preferred_username") : "")
                            .build();

                    ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

                    return chain.filter(mutatedExchange);
                });
    }


}
