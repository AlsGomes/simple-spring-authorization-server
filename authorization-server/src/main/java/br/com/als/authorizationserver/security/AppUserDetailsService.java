package br.com.als.authorizationserver.security;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.als.authorizationserver.domain.model.Permission;
import br.com.als.authorizationserver.domain.model.User;

@Service
public class AppUserDetailsService implements UserDetailsService {
	
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		User user = getSimpleUser();
		return new SecurityUser(user, getGrantedAuthorities(user));
	}

	private User getSimpleUser() {
		User user = User.builder()
				.id(1L)
				.name("Alisson")
				.pwd(passwordEncoder.encode("1234"))
				.email("myemail@hotmail.com")
				.build();
		
		Permission canCreate = Permission.builder()
				.id(1L)
				.description("ROLE_CAN_CREATE")
				.build();
		Permission canRead = Permission.builder()
				.id(2L)
				.description("ROLE_CAN_READ")
				.build();
		Permission canUpdate = Permission.builder()
				.id(3L)
				.description("ROLE_CAN_UPDATE")
				.build();
		Permission canDelete = Permission.builder()
				.id(4L)
				.description("ROLE_CAN_DELETE")
				.build();
		
		user.getPermissions().addAll(Arrays.asList(
				canCreate, 
				canRead, 
				canUpdate, 
				canDelete
				));
		
		return user;
	}

	private Collection<? extends GrantedAuthority> getGrantedAuthorities(User user) {
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		user.getPermissions()
				.forEach(p -> authorities.add(new SimpleGrantedAuthority(p.getDescription().toUpperCase())));
		return authorities;
	}
}