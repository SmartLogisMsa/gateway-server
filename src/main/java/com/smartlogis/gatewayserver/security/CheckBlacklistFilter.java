package com.smartlogis.gatewayserver.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.smartlogis.gatewayserver.auth.BlacklistService;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class CheckBlacklistFilter implements GlobalFilter {

	private final BlacklistService blacklistService;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.map(securityContext -> securityContext == null ? null : securityContext.getAuthentication())
			.flatMap(auth -> {
				if (!(auth instanceof JwtAuthenticationToken JwtAuth)) {
					return chain.filter(exchange);
				}

				String tokenId = JwtAuth.getToken().getId();
				if (blacklistService.isBlacklist(tokenId)) {
					exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
					return exchange.getResponse().setComplete();
				}

				return chain.filter(exchange);
			});
	}
}
