package com.smartlogis.gatewayserver.auth;

public interface BlacklistService {
	public void add(String tokenId, long expiration);
	public void remove(String tokenId);
	public boolean isBlacklist(String tokenId);
}
