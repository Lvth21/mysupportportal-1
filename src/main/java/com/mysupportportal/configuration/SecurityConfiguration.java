package com.mysupportportal.configuration;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import static com.mysupportportal.constant.SecurityConstant.*;
import com.mysupportportal.filter.JwtAuthorizationFilter;
import com.mysupportportal.filter.JwtAccessDeniedHanlder;
import com.mysupportportal.filter.JwtAuthenticationEntryPoint;

/*
 * When prePostEnabled = true is set, it enables support for the @PreAuthorize, 
 * @PostAuthorize, @PreFilter, and @PostFilter annotations.

The @PreAuthorize annotation can be used to specify security constraints on 
method invocations. It allows you to specify a SpEL expression to be evaluated 
before the method is invoked. If the expression returns false, the method will
not be invoked and an exception will be thrown.

The @PostAuthorize annotation can be used to specify security constraints on method 
invocations after the method has been executed. It allows you to specify a SpEL 
expression to be evaluated after the method is invoked. If the expression returns 
false, an exception will be thrown.

The @PreFilter and @PostFilter annotations can be used to filter a collection 
of objects before or after a method is invoked. These annotations allow you to 
specify a SpEL expression to be evaluated for each element in the collection. 
If the expression returns false, the element will be removed from the collection.

In general, prePostEnabled = true is used to enable Spring Security's method-level 
security, in which you can use the annotations mentioned above to secure your 
application's methods.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration {

	private JwtAuthorizationFilter jwtAuthorizationFilter;
	private JwtAccessDeniedHanlder jwtAccessDeniedHandler;
	private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
	private UserDetailsService userDetailsService;
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	/*
	 * the dependencies are clearly identified. There is no way to forget one when
	 * testing, or instantiating the object in any other circumstance (like creating
	 * the bean instance explicitly in a config class) the dependencies can be
	 * final, which helps with robustness and thread-safety you don't need
	 * reflection to set the dependencies. InjectMocks is still usable, but not
	 * necessary. You can just create mocks by yourself and inject them by simply
	 * calling the constructor
	 */
	@Autowired
	public SecurityConfiguration(JwtAuthorizationFilter jwtAuthorizationFilter,
			JwtAccessDeniedHanlder jwtAccessDeniedHandler, JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
			@Qualifier("userDetailsService") UserDetailsService userDetailsService,
			BCryptPasswordEncoder bCryptPasswordEncoder) {
		super();
		this.jwtAuthorizationFilter = jwtAuthorizationFilter;
		this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
		this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
		this.userDetailsService = userDetailsService;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}

	/*
	 * The method takes an HttpSecurity object as an argument, which is used to
	 * configure the security of the application's HTTP endpoints.
	 * 
	 * The method starts by getting the shared object of type
	 * AuthenticationManagerBuilder from the HttpSecurity object. This
	 * AuthenticationManagerBuilder is used to configure the authentication manager.
	 * 
	 * The userDetailsService(userDetailsService) method is used to set the
	 * UserDetailsService implementation that will be used to load user details for
	 * authentication. The userDetailsService variable is an instance of the
	 * UserDetailsService implementation that needs to be set.
	 * 
	 * The passwordEncoder(bCryptPasswordEncoder) method is used to set the password
	 * encoder that will be used to encode and compare passwords during
	 * authentication. The bCryptPasswordEncoder variable is an instance of the
	 * password encoder that needs to be set.
	 */
	@Bean
	public AuthenticationManager authManager(HttpSecurity http) throws Exception {
		return http.getSharedObject(AuthenticationManagerBuilder.class).userDetailsService(userDetailsService)
				.passwordEncoder(bCryptPasswordEncoder).and().build();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		AuthenticationManagerBuilder authenticationManagerBuilder = http
				.getSharedObject(AuthenticationManagerBuilder.class);
		authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
		// it means that cors filter is used
		http.csrf().disable().cors().and().sessionManagement().sessionCreationPolicy(STATELESS).and()
				.authorizeRequests().antMatchers(PUBLIC_URLS).permitAll().anyRequest().authenticated().and()
				.exceptionHandling().accessDeniedHandler(jwtAccessDeniedHandler)
				.authenticationEntryPoint(jwtAuthenticationEntryPoint).and()
				.addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}
	/*
	 * Breakdown:
	 * 
	 * http.csrf().disable(): This disables the Cross-Site Request Forgery (CSRF)
	 * protection provided by Spring Security. CSRF is a security feature that helps
	 * protect against attacks where a malicious website attempts to perform
	 * unauthorized actions on your site.
	 * 
	 * http.cors(): This enables Cross-Origin Resource Sharing (CORS) support in
	 * Spring Security. CORS is a mechanism that allows a web page from one domain
	 * to access resources from another domain.
	 * 
	 * http.sessionManagement().sessionCreationPolicy(STATELESS): This sets the
	 * session creation policy to "stateless" which means that Spring Security will
	 * not create a session and will not store any information in the session. This
	 * is useful for RESTful APIs which don't need to maintain a session.
	 * 
	 * http.authorizeRequests().antMatchers(PUBLIC_URLS).permitAll().anyRequest().
	 * authenticated(): This configures the authorization rules for the application.
	 * The antMatchers(PUBLIC_URLS).permitAll() line allows all requests to URLs
	 * specified in the PUBLIC_URLS variable to be accessed without authentication.
	 * The .anyRequest().authenticated() line then requires that all other requests
	 * are authenticated.
	 * 
	 * http.exceptionHandling().accessDeniedHandler(jwtAccessDeniedHandler).
	 * authenticationEntryPoint(jwtAuthenticationEntryPoint): This configures the
	 * AccessDeniedHandler and AuthenticationEntryPoint to handle unauthorized and
	 * unauthenticated requests respectively.
	 * 
	 * http.addFilterBefore(jwtAuthorizationFilter,
	 * UsernamePasswordAuthenticationFilter.class): This adds the
	 * jwtAuthorizationFilter filter to the filter chain, before the
	 * UsernamePasswordAuthenticationFilter.
	 * 
	 * return http.build(): Finally, it returns the SecurityFilterChain object that
	 * contains all the security filters for the application.
	 */
}
