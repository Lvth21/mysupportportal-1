package com.mysupportportal.utility;
import static java.util.Arrays.stream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;

import static com.mysupportportal.constant.SecurityConstant.*;
import com.mysupportportal.domain.UserPrincipal;


@Component
public class JWTTokenProvider {
	//best practice is to keep it in a secure server and access it with a configuration file
	@Value("${jwt.secret}") //in this way can be called from the properties file
	private String secret;
	
	//userPrincipal is created once the user is verified
	public String generateJwtToken(UserPrincipal userPrincipal) {//generates the token once the user logged in
		String[] claims = getClaimsFromUser(userPrincipal); //claims == authorizations
		return JWT.create()
				.withIssuer(GET_ARRAYS_LLC)//your company name
				.withAudience(GET_ARRAYS_ADMINISTRATION) //the audience i defined(administration)
				.withIssuedAt(new Date())
				.withSubject(userPrincipal.getUsername())//unique identifier for the user
				.withArrayClaim(AUTHORITIES, claims)// is a method from JWT library to add a custom claim called "authorities" to the JWT token, 	
//where claims is an array of strings. The custom claim is an additional piece of information that can be stored in the JWT token.
//In this specific case, the method is adding an array of claims, which represents the granted authorities of the user, 
//	to the JWT token. These authorities will be encoded into the JWT and can be used by the recipient to determine the permissions of the user.
				.withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.sign(Algorithm.HMAC512(secret.getBytes()));
	}
	
	public List<GrantedAuthority> getAuthorities(String token){
		String[] claims = getClaimsFromToken(token);
		return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}
	//get the autentication of the user: if I can verify that a token is correct, i have to
	//tell spring security to get me the authentication of the user and then set that authentication
	//in the spring security context 
	public Authentication getAuthentication (String username, List<GrantedAuthority> authorities, HttpServletRequest request) {
		
		UsernamePasswordAuthenticationToken userPasswordAuthToken = new 
//A null value, which represents the password of the user, since the authentication has already been performed and the token has been verified
				UsernamePasswordAuthenticationToken(username, null, authorities);
		//Then it sets the details of the authentication token, by creating a new instance of the WebAuthenticationDetailsSource
		//class and calling the buildDetails(request) method on it,
		//passing in the request parameter, to extract information from the request to use as the details of the token.
		userPasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
		return userPasswordAuthToken;//gets the authentication once you verified the token (this user is authenticated, process the request!)
		/*
		 * it creates an instance of the UsernamePasswordAuthenticationToken class,
		 * which implements the Authentication interface and sets the details of the token 
		 * with the request parameter and returns it
		 */
	}

	//check if the token is valid:
	public boolean isTokenValid(String username, String token) {
		JWTVerifier verifier = getJWTVerifier();
		
		return StringUtils.isNotEmpty(username) && !isTokenExpired(verifier, token);
	}
//returns the value of the "sub" claim of the token. This claim is the subject of the JWT token, usually an user ID or an username.
	public String getSubject(String token) {
		JWTVerifier verifier = getJWTVerifier();
		return verifier.verify(token).getSubject();
	}
	
	
	
	private boolean isTokenExpired(JWTVerifier verifier, String token) {
//.verify return a DecodedJWT Performs the verification against the given Token.
		Date expiration = verifier.verify(token).getExpiresAt();
		return expiration.before(new Date());
	}

	private String[] getClaimsFromToken(String token) {
		JWTVerifier verifier = getJWTVerifier();
		return verifier.verify(token)//Performs the verification against the given Token. Return a verified and DecodedJWT.
				.getClaim(AUTHORITIES).asArray(String.class);
	}

	//This creates a new verifier that will check that the token is signed with the provided algorithm and
	//will check that the token has an "iss" claim with the value of `GET_ARRAYS_LLC`
	private JWTVerifier getJWTVerifier() {
		
		JWTVerifier verifier;
		try {
			Algorithm algorithm = Algorithm.HMAC512(secret);
			verifier = JWT.require(algorithm).withIssuer(GET_ARRAYS_LLC).build();
		} catch (JWTVerificationException exception) {
			throw new JWTVerificationException(TOKEN_CONNOT_BE_VERIFIED);//we don't pass exception because we don't want to reveal critical info
		}

		
		return verifier;
	}

	private String[] getClaimsFromUser(UserPrincipal user) {
		
		List<String> authorities = new ArrayList<>();
		
		for(GrantedAuthority grantedAuthority : user.getAuthorities()) {
			authorities.add(grantedAuthority.getAuthority());
		}
		
		return authorities.toArray(new String[0]);
//		So passing new String[0] as an argument to the toArray() method is saying 
//		that the returned array should be of the type String[] but the size of the
//		array will be determined by the size of the list, which is the number of authorities the user has.
	}

}
