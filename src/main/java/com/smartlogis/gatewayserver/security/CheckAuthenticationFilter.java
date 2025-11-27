package com.smartlogis.gatewayserver.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class CheckAuthenticationFilter implements GlobalFilter, Ordered {

	@Override
	public int getOrder() {
		return HIGHEST_PRECEDENCE;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.flatMap(auth -> {
				log.info("[SmartLogis] Check authentication");

				if (!(auth instanceof JwtAuthenticationToken)) {
					log.warn("[SmartLogis] Authentication is not JwtAuthenticationToken");
					return chain.filter(exchange);
				}

				Jwt jwt = ((JwtAuthenticationToken)auth).getToken();
				exchange.getAttributes().put("jwt", jwt);

				return chain.filter(exchange);
			})
			.switchIfEmpty(chain.filter(exchange));
	}
}
