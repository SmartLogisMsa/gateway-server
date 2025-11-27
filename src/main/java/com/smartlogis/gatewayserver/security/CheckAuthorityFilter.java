package com.smartlogis.gatewayserver.security;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import com.smartlogis.gatewayserver.auth.BlacklistService;
import com.smartlogis.gatewayserver.auth.RedisUserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class CheckAuthorityFilter implements GlobalFilter, Ordered {

	private final RedisUserService redisUserService;
	private final BlacklistService blacklistService;

	@Override
	public int getOrder() {
		return HIGHEST_PRECEDENCE + 20;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		Jwt jwt = exchange.getAttribute("jwt");
		if (jwt == null ) return chain.filter(exchange);

		log.info("[SmartLogis] Check authority");

		Set<String> roles = TokenHelper.extractRoles(jwt).stream()
			.filter(r -> r.startsWith("ROLE_"))
			.map(r -> r.replace("ROLE_", ""))
			.collect(Collectors.toSet());

		String userId = jwt.getSubject();

		return redisUserService.getRoles(userId)
			.flatMap(cache -> {
				if (!cache.equals(roles)) {
					log.warn("[SmartLogis] Mismatched user roles. {} ≠ {}", roles, cache);

					long expiration = TokenHelper.getExpiration(jwt.getExpiresAt());
					blacklistService.add(jwt.getId(), expiration);

					return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
				} else {
					return chain.filter(exchange);
				}
			});
	}
}
