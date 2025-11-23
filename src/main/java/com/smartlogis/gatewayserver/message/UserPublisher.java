package com.smartlogis.gatewayserver.message;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@Component
@RefreshScope
@RequiredArgsConstructor
@EnableConfigurationProperties(RabbitUserProperties.class)
public class UserPublisher {

	private final RabbitTemplate rabbitTemplate;
	private final RabbitUserProperties properties;

	public void publish(UserRoutingKey key, UserRoleMessage payload) {
		rabbitTemplate.convertAndSend(properties.exchange(), key.getValue(), payload);
	}
}
