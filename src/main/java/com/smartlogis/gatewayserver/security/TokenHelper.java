package com.smartlogis.gatewayserver.security;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.jwt.Jwt;

public class TokenHelper {
	public static Set<String> extractRoles(Jwt jwt) {
		Set<String> result = new HashSet<>();
		if (jwt.hasClaim("roles")) {
			Object v = jwt.getClaim("roles");
			if (v instanceof Collection) {
				((Collection<?>) v).forEach(r -> result.add(r.toString()));
			}
		} else if (jwt.hasClaim("realm_access")) {
			Map<String,Object> realmAccess = jwt.getClaim("realm_access");
			Object r = realmAccess.get("roles");
			if (r instanceof Collection) {
				((Collection<?>) r).forEach(role -> result.add(role.toString()));
			}
		} else if (jwt.hasClaim("resource_access")) {
			Map<String,Object> resourceAccess = jwt.getClaim("resource_access");
			resourceAccess.values().forEach(v -> {
				if (v instanceof Map) {
					Object rr = ((Map<?,?>)v).get("roles");
					if (rr instanceof Collection) {
						((Collection<?>) rr).forEach(role -> result.add(role.toString()));
					}
				}
			});
		}
		return result;
	}
}
