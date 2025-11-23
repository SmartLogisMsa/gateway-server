package com.smartlogis.gatewayserver.security;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.smartlogis.gatewayserver.auth.RedisUserService;
import com.smartlogis.gatewayserver.auth.UserServiceClient;
import com.smartlogis.gatewayserver.message.UserRoleMessage;
import com.smartlogis.gatewayserver.message.UserPublisher;
import com.smartlogis.gatewayserver.message.UserRoutingKey;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class CheckRoleFilter implements GatewayFilter, Ordered {

	private final RedisUserService redisUserService;

	private final UserPublisher userPublisher;
	private final UserServiceClient userServiceClient;

	@Override
	public int getOrder() {
		return 2;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.flatMap(auth -> {
				String userId = ((JwtAuthenticationToken) auth).getToken().getSubject();
				Set<String> cache = redisUserService.getRoles(userId);

				// 캐시가 없는 경우, user-service 호출
				if (cache.isEmpty()) {
					cache = userServiceClient.getRoles(userId);
				}

				Set<String> roles = auth.getAuthorities().stream()
					.map(a -> a.getAuthority().replace("ROLE_", ""))
					.collect(Collectors.toSet());

				// token 역할과 DB 역할이 일치하지 않는 경우,
				if (!cache.equals(roles)) {
					UserRoleMessage userRoleMessage = new UserRoleMessage(userId, LocalDateTime.now());
					userPublisher.publish(UserRoutingKey.ROLE_MISMATCH, userRoleMessage);

					exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
					return exchange.getResponse().setComplete();
				}

				exchange.getRequest().mutate()
					.header("X-User-Roles", String.join(",", roles))
					.build();

				return chain.filter(exchange);
			});

	}
}
