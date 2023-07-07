package com.mysupportportal.listener;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import com.mysupportportal.service.LoginAttemptService;

@Component
public class AuthenticationFaluireListener {

	private LoginAttemptService loginAttemptService;

	@Autowired
	public AuthenticationFaluireListener(LoginAttemptService loginAttemptService) {
		super();
		this.loginAttemptService = loginAttemptService;
	}

	@EventListener // it's going to be fired every time the user fails the auth
	public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
		Object principal = event.getAuthentication().getPrincipal();
		if (principal instanceof String) {
			String username = (String) event.getAuthentication().getPrincipal();
			loginAttemptService.addUserToLoginAttemptCache(username);
		}

	}
	/*
	 * This code is an EventListener that listens for an
	 * AuthenticationFailureBadCredentialsEvent, which is triggered when an
	 * authentication attempt fails due to bad credentials (e.g. incorrect
	 * password). When this event is fired, the listener's onAuthenticationFailure
	 * method is executed.
	 * 
	 * The method first checks if the "principal" object, which represents the user
	 * trying to authenticate, is a string (i.e. a username). If it is, it retrieves
	 * the username and calls the addUserToLoginAttemptCache method on an instance
	 * of a loginAttemptService. This method probably adds the username to a cache
	 * of failed login attempts, which can be used for tracking or blocking further
	 * login attempts from that user.
	 */
}
