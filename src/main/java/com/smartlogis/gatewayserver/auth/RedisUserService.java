package com.smartlogis.gatewayserver.auth;

import java.util.Set;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RedisUserService {

	private final StringRedisTemplate redisTemplate;

	public Set<String> getRoles(String userId) {
		String roles = redisTemplate.opsForValue().get("user:" + userId);
		if (roles == null || roles.isEmpty()) return Set.of();
		return Set.of(roles.split(","));
	}

	public boolean hasRole(String userId, String role) {
		return getRoles(userId).contains(role);
	}
}
