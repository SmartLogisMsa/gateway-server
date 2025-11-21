package com.smartlogis.gatewayserver.config;

import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {
	@Bean
	public GroupedOpenApi userAPI() {
		return GroupedOpenApi.builder()
			.group("user-api")
			.displayName("USER API")
			.pathsToMatch("/v1/user/**")
			.build();
	}

	@Bean
	public GroupedOpenApi hubAPI() {
		return GroupedOpenApi.builder()
			.group("hub-api")
			.displayName("HUB API")
			.pathsToMatch("/v1/hub/**")
			.build();
	}

	@Bean
	public GroupedOpenApi orderAPI() {
		return GroupedOpenApi.builder()
			.group("order-api")
			.displayName("ORDER API")
			.pathsToMatch("/v1/order/**")
			.build();
	}

	@Bean
	public GroupedOpenApi companyAPI() {
		return GroupedOpenApi.builder()
			.group("company-api")
			.displayName("COMPANY API")
			.pathsToMatch("/v1/company/**")
			.build();
	}

	@Bean
	public GroupedOpenApi productAPI() {
		return GroupedOpenApi.builder()
			.group("product-api")
			.displayName("PRODUCT API")
			.pathsToMatch("/v1/product/**")
			.build();
	}
}
