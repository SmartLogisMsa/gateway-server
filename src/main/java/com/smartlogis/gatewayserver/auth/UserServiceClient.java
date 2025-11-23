package com.smartlogis.gatewayserver.auth;

import java.util.Set;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(value = "user-service")
public interface UserServiceClient {
	@GetMapping("/v1/internal/users/{userId}/roles")
	Set<String> getRoles(@PathVariable String userId);
}
