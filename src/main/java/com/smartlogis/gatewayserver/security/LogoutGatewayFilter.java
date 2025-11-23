package com.smartlogis.gatewayserver.security;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.smartlogis.gatewayserver.auth.BlacklistService;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE + 30)
public class LogoutGatewayFilter implements GatewayFilter {

	private final BlacklistService blacklistService;

	private static final String LOGOUT_PATH = "/v1/users/logout";

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.flatMap(auth -> {
				if (!exchange.getRequest().getPath().value().equals(LOGOUT_PATH)) {
					return chain.filter(exchange);
				}

				JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) auth;
				Jwt jwt = jwtAuth.getToken();

				long expiration = jwt.getExpiresAt().getEpochSecond() - System.currentTimeMillis() / 1000;
				blacklistService.add(jwt.getId(), expiration);

				return chain.filter(exchange)
					.doFinally(result -> {
						if (!exchange.getResponse().getStatusCode().is2xxSuccessful()) {
							blacklistService.remove(jwt.getId());
						}
					});
			});
	}
}
