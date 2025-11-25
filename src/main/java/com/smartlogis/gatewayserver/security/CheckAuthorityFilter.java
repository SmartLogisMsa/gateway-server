package com.smartlogis.gatewayserver.security;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import com.smartlogis.gatewayserver.auth.BlacklistService;
import com.smartlogis.gatewayserver.auth.UserServiceClient;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE+1)
public class CheckAuthorityFilter implements GlobalFilter, Ordered {

	private final UserServiceClient userServiceClient;
	private final BlacklistService blacklistService;

	@Override
	public int getOrder() {
		return HIGHEST_PRECEDENCE + 10;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.flatMap(auth -> {
				if (!(auth instanceof JwtAuthenticationToken)) return chain.filter(exchange);

				Jwt jwt = ((JwtAuthenticationToken) auth).getToken();

				Set<String> roles = TokenHelper.extractRoles(jwt).stream()
					.filter(r -> r.startsWith("ROLE_"))
					.map(r -> r.replace("ROLE_", ""))
					.collect(Collectors.toSet());

				String userId = jwt.getSubject();
				return userServiceClient.getRoles(userId)
					.flatMap(cache -> {

						if (!cache.equals(roles)) {
							log.warn("[CheckAuthorityFilter] Mismatched user roles.");

							long expiration = Math.max(0, jwt.getExpiresAt().getEpochSecond() - System.currentTimeMillis() / 1000);
							blacklistService.add(jwt.getId(), expiration);

							return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
						} else {
							return chain.filter(exchange);
						}
					});
			})
			.switchIfEmpty(chain.filter(exchange));
	}
}
