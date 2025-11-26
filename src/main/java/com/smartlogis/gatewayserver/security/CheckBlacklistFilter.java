package com.smartlogis.gatewayserver.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import com.smartlogis.gatewayserver.auth.BlacklistService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class CheckBlacklistFilter implements GlobalFilter, Ordered {

	private final BlacklistService blacklistService;

	@Override
	public int getOrder() {
		return HIGHEST_PRECEDENCE;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.flatMap(auth -> {
				if (!(auth instanceof JwtAuthenticationToken)) return chain.filter(exchange);

				String tokenId =  ((JwtAuthenticationToken) auth).getToken().getId();

				if (blacklistService.isBlacklist(tokenId)) {
					log.warn("[CheckBlacklistFilter] Token is blacklisted.");
					return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
				} else {
					return chain.filter(exchange);
				}
			})
			.switchIfEmpty(chain.filter(exchange));
	}
}
