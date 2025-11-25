package com.smartlogis.gatewayserver.auth;

import java.util.Set;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

@Component
public class UserServiceClient {

	private final WebClient webClient;

	public UserServiceClient(WebClient.Builder builder) {
		this.webClient = builder.baseUrl("http://localhost:3010").build();
	}

	@Cacheable(cacheNames = "user", key = "#userId", unless = "#result.isEmpty()")
	public Mono<Set<String>> getRoles(String userId) {
		return webClient.get()
			.uri("/v1/internal/users/{userId}/roles", userId)
			.retrieve()
			.bodyToMono(new ParameterizedTypeReference<Set<String>>() {});
	}
}
