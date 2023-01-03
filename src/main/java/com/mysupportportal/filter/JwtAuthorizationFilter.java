package com.mysupportportal.filter;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import static com.mysupportportal.constant.SecurityConstant.*;

import com.mysupportportal.utility.JWTTokenProvider;

@Component
//this class is going to authorize or not any request, but just once.
public class JwtAuthorizationFilter extends OncePerRequestFilter {
	
	private JWTTokenProvider jwtTokenProvider;
	
	
//whenever the class is costructed, we'll have a jwtTokenProvider available
	public JwtAuthorizationFilter(JWTTokenProvider jwtTokenProvider) {
		this.jwtTokenProvider = jwtTokenProvider;
	}



	@Override//this method is going to fire every time a request comes in: we''ll make sure the token and user is valid and then set the user as authenticated
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		//fist we have to make sure that the request is not OPTION, cuz the OPTION is used from the client to collect info
		// about the server. it'always the first request before the actual request and it needs to pass through. 
		
		
		if(request.getMethod().equalsIgnoreCase(OPTIONS_HTTP_METHOD)) {
			response.setStatus(HttpStatus.OK.value());
		}else {//here we are going to take the token, that is in the header
			String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
			if(authorizationHeader == null || !authorizationHeader.startsWith(TOKEN_PREFIX) ) {
				//if the auth is null or the header doesnt start with Bearer than this is not the auth header we are looking for
				filterChain.doFilter(request, response);
				return;
			}
			String token = authorizationHeader.substring(TOKEN_PREFIX.length());
            String username = jwtTokenProvider.getSubject(token); //this part of the 'if' is not needed since we are not in the session and can be removed.
            if (jwtTokenProvider.isTokenValid(username, token) && SecurityContextHolder.getContext().getAuthentication() == null) {
                List<GrantedAuthority> authorities = jwtTokenProvider.getAuthorities(token);
                Authentication authentication = jwtTokenProvider.getAuthentication(username, authorities, request);
                SecurityContextHolder.getContext().setAuthentication(authentication);//pass the authentication to spring security context
            } else {
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request, response);//Causes the next filter in the chain to be invoked, or if the callingfilter is the last filter in the chain, 
        										//causes the resource at the end ofthe chain to be invoked.
    }
}