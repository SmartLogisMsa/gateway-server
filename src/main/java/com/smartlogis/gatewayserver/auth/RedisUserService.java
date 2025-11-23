package com.smartlogis.gatewayserver.auth;

import java.util.Set;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RedisUserService {

	private final UserServiceClient userServiceClient;

	@Cacheable(cacheNames = "user", key = "#userId")
	public Set<String> getRoles(String userId) {
		return userServiceClient.getRoles(userId);
	}
}
