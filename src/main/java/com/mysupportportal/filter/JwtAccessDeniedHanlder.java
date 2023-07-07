package com.mysupportportal.filter;

import static com.mysupportportal.constant.SecurityConstant.ACCESS_DENIED_MESSAGE;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.IOException;
import java.io.OutputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mysupportportal.domain.HttpResponse;

@Component
public class JwtAccessDeniedHanlder implements AccessDeniedHandler {
	/*
	 * This is a Java class that implements the AccessDeniedHandler interface. 
	 * The AccessDeniedHandler interface is part of the Spring Security framework
	 *  and it provides a way to handle access denied exceptions that occur when 
	 *  a user tries to access a protected resource without the necessary permissions.
	 *  
	 *  The class implements a single method, handle(HttpServletRequest request, 
	 *  HttpServletResponse response, AccessDeniedException exception), which is 
	 *  called when an access denied exception occurs.
	 */

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException exception) throws IOException, ServletException {
		HttpResponse httpReponse = new HttpResponse(UNAUTHORIZED.value(),
				UNAUTHORIZED, UNAUTHORIZED.getReasonPhrase().toUpperCase(), ACCESS_DENIED_MESSAGE );
		response.setContentType(APPLICATION_JSON_VALUE);
		response.setStatus(UNAUTHORIZED.value());
		OutputStream outputStream = response.getOutputStream(); //Returns a ServletOutputStream suitable for writing binary data in the response.
		ObjectMapper mapper = new ObjectMapper();
		mapper.writeValue(outputStream, httpReponse);//Method that can be used to serialize any Java value asJSON output, using output stream provided (using encoding JsonEncoding.UTF8). 

		outputStream.flush();
		
	}

}
