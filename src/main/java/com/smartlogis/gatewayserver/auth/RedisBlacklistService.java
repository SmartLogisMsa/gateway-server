package com.smartlogis.gatewayserver.auth;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisBlacklistService implements BlacklistService {

	private final StringRedisTemplate redisTemplate;

	@Override
	public void add(String tokenId, long expiration) {
		if (expiration <= 0) {
			log.warn("[RedisBlacklistService] Invalid expiration value: {}", expiration);
			return;
		}
		redisTemplate.opsForValue().set("blacklist:" + tokenId, "true", expiration, TimeUnit.SECONDS);
	}

	@Override
	public void remove(String tokenId) {
		redisTemplate.delete("blacklist:" + tokenId);
	}

	@Override
	public boolean isBlacklist(String tokenId) {
		return redisTemplate.hasKey("blacklist:" + tokenId);
	}
}
