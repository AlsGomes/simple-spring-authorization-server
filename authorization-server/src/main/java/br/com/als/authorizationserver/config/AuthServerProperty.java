package br.com.als.authorizationserver.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Component
@ConfigurationProperties("auth-server")
@Getter
public class AuthServerProperty {
	
	private final Security security = new Security();	

	@Getter
	@Setter
	public static class Security {
		private List<String> allowedRedirects;
		private String authServerUrl;
	}
}
