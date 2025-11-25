package com.smartlogis.gatewayserver.security;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.smartlogis.gatewayserver.auth.BlacklistService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class LogoutHandlerFilter implements GatewayFilter, Ordered {

	private final BlacklistService blacklistService;

	@Override
	public int getOrder() {
		return HIGHEST_PRECEDENCE + 30;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.flatMap(auth -> {
				if (!(auth instanceof JwtAuthenticationToken)) return chain.filter(exchange);

				JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) auth;
				Jwt jwt = jwtAuth.getToken();

				long expiration = Math.max(0, jwt.getExpiresAt().getEpochSecond() - System.currentTimeMillis() / 1000);
				blacklistService.add(jwt.getId(), expiration);
				log.debug("[LogoutGatewayFilter] Add blacklist");

				return chain.filter(exchange)
					.doFinally(result -> {
						if (!exchange.getResponse().getStatusCode().is2xxSuccessful()) {
							blacklistService.remove(jwt.getId());
							log.debug("[LogoutGatewayFilter] Remove blacklist");
						}
					});
			})
			.switchIfEmpty(Mono.defer(() -> chain.filter(exchange)));
	}
}
