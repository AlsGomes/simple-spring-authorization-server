package br.com.als.authorizationserver.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

import br.com.als.authorizationserver.domain.model.User;
import lombok.Getter;

@Getter
public class SecurityUser extends org.springframework.security.core.userdetails.User {
	private static final long serialVersionUID = 1L;

	private User user;

	public SecurityUser(User user, Collection<? extends GrantedAuthority> authorities) {
		super(user.getEmail(), user.getPwd(), authorities);
		this.user = user;
	}
}