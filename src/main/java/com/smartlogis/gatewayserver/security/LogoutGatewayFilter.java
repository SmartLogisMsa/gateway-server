package com.smartlogis.gatewayserver.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.smartlogis.gatewayserver.auth.BlacklistService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class LogoutGatewayFilter implements GlobalFilter, Ordered {

	private static final String LOGOUT_PATH = "/v1/users/logout";

	private final BlacklistService blacklistService;

	@Override
	public int getOrder() {
		return HIGHEST_PRECEDENCE + 30;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		if (!exchange.getRequest().getPath().value().equals(LOGOUT_PATH)) {
			return chain.filter(exchange);
		}

		Jwt jwt = exchange.getAttribute("jwt");
		if (jwt == null) return chain.filter(exchange);

		log.info("[SmartLogis] Logout gateway filter");

		long expiration = Math.max(0, jwt.getExpiresAt().getEpochSecond() - System.currentTimeMillis() / 1000);
		blacklistService.add(jwt.getId(), expiration);
		log.debug("[SmartLogis] Add blacklist");

		return chain.filter(exchange)
			.doFinally(result -> {
				log.info("[SmartLogis] Logout gateway filter response");
				if (!exchange.getResponse().getStatusCode().is2xxSuccessful()) {
					blacklistService.remove(jwt.getId());
					log.debug("[SmartLogis] Remove blacklist");
				}
			});
	}
}
