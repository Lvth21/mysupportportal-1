package com.mysupportportal.listener;

import com.mysupportportal.domain.UserPrincipal;
import com.mysupportportal.service.LoginAttemptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSuccessListener {
    private LoginAttemptService loginAttemptService;

    @Autowired
    public AuthenticationSuccessListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Object principal = event.getAuthentication().getPrincipal();//The identity of the principal being authenticated. In the case of an authenticationrequest
        if(principal instanceof UserPrincipal) {					// with username and password, this would be the username. Callers areexpected to populate  
            UserPrincipal user = (UserPrincipal) event.getAuthentication().getPrincipal();//the principal for an authentication request.
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
        }
    }
}
