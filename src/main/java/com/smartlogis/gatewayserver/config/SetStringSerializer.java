package com.smartlogis.gatewayserver.config;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;

public class SetStringSerializer implements RedisSerializer<Set<String>> {
	@Override
	public byte[] serialize(Set<String> value) throws SerializationException {
		if (value == null || value.isEmpty()) return new byte[0];

		return String.join(",", value).getBytes(StandardCharsets.UTF_8);
	}

	@Override
	public Set<String> deserialize(byte[] bytes) throws SerializationException {
		if (bytes == null || bytes.length == 0) return new HashSet<>();

		String str = new String(bytes, StandardCharsets.UTF_8);
		return new HashSet<>(Arrays.asList(str.split(",")));
	}
}
