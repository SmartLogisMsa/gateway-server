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
			.pathsToMatch("/v1/users/**")
			.build();
	}

	@Bean
	public GroupedOpenApi aiApi() {
		return GroupedOpenApi.builder()
			.group("ai-api")
			.displayName("AI API")
			.pathsToMatch("/v1/ai/**")
			.build();
	}

	@Bean
	public GroupedOpenApi notificationApi() {
		return GroupedOpenApi.builder()
			.group("notification-api")
			.displayName("NOTIFICATION API")
			.pathsToMatch("/v1/notifications/**")
			.build();
	}

	@Bean
	public GroupedOpenApi hubAPI() {
		return GroupedOpenApi.builder()
			.group("hub-api")
			.displayName("HUB API")
			.pathsToMatch("/v1/hubs/**")
			.build();
	}

	@Bean
	public GroupedOpenApi companyAPI() {
		return GroupedOpenApi.builder()
			.group("company-api")
			.displayName("COMPANY API")
			.pathsToMatch("/v1/companies/**")
			.build();
	}

	@Bean
	public GroupedOpenApi productAPI() {
		return GroupedOpenApi.builder()
			.group("product-api")
			.displayName("PRODUCT API")
			.pathsToMatch("/v1/products/**")
			.build();
	}

	@Bean
	public GroupedOpenApi deliveryAPI() {
		return GroupedOpenApi.builder()
			.group("delivery-api")
			.displayName("DELIVERY API")
			.pathsToMatch("/v1/deliveries/**")
			.build();
	}
}
