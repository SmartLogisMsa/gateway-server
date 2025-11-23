package com.smartlogis.gatewayserver.message;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum UserRoutingKey {
	ROLE_MISMATCH("user.role.mismatch"),
	;

	private final String value;
}
