package com.springsecurity.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import com.google.common.net.HttpHeaders;

@ConfigurationProperties(prefix = "application.jwt")
@Component
public class JwtConfig {

	private String secretKey;
	private String tokenPrefix;
	private Long tokenExpirationAfterDays;

	public JwtConfig() {

	}

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}

	public String getTokenPrefix() {
		return tokenPrefix;
	}

	public void setTokenPrefix(String tokenPrefix) {
		this.tokenPrefix = tokenPrefix;
	}

	public Long getTokenExpirationAfterDays() {
		return tokenExpirationAfterDays;
	}

	public void setTokenExpirationAfterDays(Long tokenExpirationAfterDays) {
		this.tokenExpirationAfterDays = tokenExpirationAfterDays;
	}

	public String getAuthorizationHeader() {
		return HttpHeaders.AUTHORIZATION;
	}

}
