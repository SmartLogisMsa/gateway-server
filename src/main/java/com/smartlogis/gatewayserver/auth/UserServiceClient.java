package com.smartlogis.gatewayserver.auth;

import java.util.Set;

import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

@Component
public class UserServiceClient {

	private final WebClient webClient;

	public UserServiceClient(@LoadBalanced WebClient.Builder builder) {
		this.webClient = builder.baseUrl("lb://user-service").build();
	}

	public Mono<Set<String>> getRoles(String userId) {
		return webClient.get()
			.uri("/v1/internal/users/roles/{userId}", userId)
			.retrieve()
			.bodyToMono(new ParameterizedTypeReference<Set<String>>() {});
	}
}
