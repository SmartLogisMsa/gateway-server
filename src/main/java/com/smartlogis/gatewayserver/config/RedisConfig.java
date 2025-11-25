package com.smartlogis.gatewayserver.config;

import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

	@Bean
	public ReactiveRedisTemplate<String, Set<String>> setStringRedisTemplate(ReactiveRedisConnectionFactory factory) {
		SetStringSerializer setStringSerializer = new SetStringSerializer();

		RedisSerializationContext<String, Set<String>> context =
			RedisSerializationContext.<String, Set<String>>newSerializationContext(new StringRedisSerializer())
				.key(new StringRedisSerializer())
				.value(setStringSerializer)
				.hashKey(new StringRedisSerializer())
				.hashValue(setStringSerializer)
				.build();

		return new ReactiveRedisTemplate<>(factory, context);
	}
}
