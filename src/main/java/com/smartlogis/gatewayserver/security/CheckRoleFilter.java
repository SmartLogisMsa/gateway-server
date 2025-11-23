package com.smartlogis.gatewayserver.security;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.smartlogis.gatewayserver.auth.RedisUserService;
import com.smartlogis.gatewayserver.auth.UserServiceClient;
import com.smartlogis.gatewayserver.message.UserPublisher;
import com.smartlogis.gatewayserver.message.UserRoleMessage;
import com.smartlogis.gatewayserver.message.UserRoutingKey;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class CheckRoleFilter implements GatewayFilter, Ordered {

	private final RedisUserService redisUserService;

	private final UserPublisher userPublisher;
	private final UserServiceClient userServiceClient;

	private static final String HEADER_ROLES = "X-User-Role";

	@Override
	public int getOrder() {
		return 2;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.flatMap(auth -> {
				Jwt jwt = ((JwtAuthenticationToken) auth).getToken();

				String userId = jwt.getSubject();

				Set<String> cache = redisUserService.getRoles(userId);
				Set<String> roles = extractRoles(jwt);

				// 캐시가 없는 경우, user-service 호출
				if (cache.isEmpty()) {
					cache = userServiceClient.getRoles(userId);
				}

				// token 역할과 DB 역할이 일치하지 않는 경우,
				if (!cache.equals(roles)) {
					UserRoleMessage userRoleMessage = new UserRoleMessage(userId, LocalDateTime.now());
					userPublisher.publish(UserRoutingKey.ROLE_MISMATCH, userRoleMessage);

					exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
					return exchange.getResponse().setComplete();
				}

				exchange.getRequest().mutate()
					.header(HEADER_ROLES, roles.stream().filter(s -> s.startsWith("ROLE")).collect(Collectors.joining(",")))
					.build();

				return chain.filter(exchange);
			});
	}

	private Set<String> extractRoles(Jwt jwt) {
		Set<String> result = new HashSet<>();
		if (jwt.hasClaim("roles")) {
			Object v = jwt.getClaim("roles");
			if (v instanceof Collection) {
				((Collection<?>) v).forEach(r -> result.add(r.toString()));
			}
		} else if (jwt.hasClaim("realm_access")) {
			Map<String,Object> realmAccess = jwt.getClaim("realm_access");
			Object r = realmAccess.get("roles");
			if (r instanceof Collection) {
				((Collection<?>) r).forEach(role -> result.add(role.toString()));
			}
		} else if (jwt.hasClaim("resource_access")) {
			Map<String,Object> resourceAccess = jwt.getClaim("resource_access");
			resourceAccess.values().forEach(v -> {
				if (v instanceof Map) {
					Object rr = ((Map<?,?>)v).get("roles");
					if (rr instanceof Collection) {
						((Collection<?>) rr).forEach(role -> result.add(role.toString()));
					}
				}
			});
		}
		return result;
	}
}
