package com.smartlogis.gatewayserver.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.smartlogis.gatewayserver.security.LogoutHandlerFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class CustomFilterConfig {

	private final LogoutHandlerFilter logoutHandlerFilter;

	@Bean
	public RouteLocator logoutRouteLocator(RouteLocatorBuilder builder) {
		return builder.routes()
			.route("user-service-logout", r -> r
				.path("/v1/users/logout")
				.filters(f -> f
					.filter(logoutHandlerFilter)
					.rewritePath("/v1/users/logout", "/logout")
				)
				.uri("lb://user-service"))
			.build();
	}
}
