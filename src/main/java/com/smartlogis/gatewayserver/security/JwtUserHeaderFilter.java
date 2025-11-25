package com.smartlogis.gatewayserver.security;

import java.util.stream.Collectors;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUserHeaderFilter implements GlobalFilter, Ordered {

    private static final String HEADER_USER_ID = "X-User-Id";
    private static final String HEADER_USER_NAME = "X-User-Name";
	private static final String HEADER_ROLES = "X-User-Role";

	@Override
	public int getOrder() {
		return HIGHEST_PRECEDENCE + 20;
	}

	@Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(auth -> {
					if (!(auth instanceof JwtAuthenticationToken)) return chain.filter(exchange);

					Jwt jwt = ((JwtAuthenticationToken) auth).getToken();
					String roles = TokenHelper.extractRoles(jwt).stream()
						.filter(r -> r.startsWith("ROLE_")).collect(Collectors.joining(","));

                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
							.header(HEADER_ROLES, roles)
                            .header(HEADER_USER_ID, jwt.getSubject() != null ? jwt.getSubject() : "")
                            .header(HEADER_USER_NAME, jwt.getClaimAsString("preferred_username") != null ? jwt.getClaimAsString("preferred_username") : "")
                            .build();

                    ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

                    return chain.filter(mutatedExchange);
                })
				.switchIfEmpty(chain.filter(exchange));

    }
}
