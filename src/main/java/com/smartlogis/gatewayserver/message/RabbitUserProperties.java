package com.smartlogis.gatewayserver.message;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "rabbit.user")
public record RabbitUserProperties(
	String exchange,
	String queue,
	List<String> routingKeys
) {}