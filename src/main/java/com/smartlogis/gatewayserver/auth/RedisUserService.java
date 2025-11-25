package com.smartlogis.gatewayserver.auth;

import java.util.Set;

import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class RedisUserService {

	private final ReactiveRedisTemplate<String, Set<String>> redisTemplate;
	private final UserServiceClient userServiceClient;

	public Mono<Set<String>> getRoles(String userId) {
		String key = "user:" + userId;

		return redisTemplate.opsForValue().get(key)
			.switchIfEmpty(
				userServiceClient.getRoles(userId)
					.flatMap(roles ->
						redisTemplate.opsForValue()
							.set(key, roles)
							.thenReturn(roles)
					)
			);
	}
}
