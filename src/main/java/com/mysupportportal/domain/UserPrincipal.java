package com.mysupportportal.domain;

import java.util.Collection;
import java.util.stream.Collectors;
import static java.util.Arrays.stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
								//Provides core user information.
public class UserPrincipal implements UserDetails {//Implementations are not used directly by Spring Security for security purposes. 
													//Theysimply store user information which is later encapsulated into Authenticationobjects. 
													//This allows non-security related user information (such as email addresses,
													//telephone numbers etc) to be stored in a convenient location. 

	private User user;

	public UserPrincipal(User user) {
		this.user = user;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		return stream(this.user.getAuthorities()).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}

	@Override
	public String getPassword() {

		return this.user.getPassword();
	}

	@Override
	public String getUsername() {

		return this.user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {

		return true; // non implementata
	}

	@Override
	public boolean isAccountNonLocked() {

		return this.user.isNotLocked();
	}

	@Override
	public boolean isCredentialsNonExpired() {

		return true; // not implemented
	}

	@Override
	public boolean isEnabled() {

		return this.user.isActive();
	}

}
