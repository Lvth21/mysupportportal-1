package com.mysupportportal.filter;

import java.io.IOException;
import java.io.OutputStream;

import static org.springframework.http.HttpStatus.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.stereotype.Component;

import static com.mysupportportal.constant.SecurityConstant.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mysupportportal.domain.HttpResponse;

@Component // whenever the user fail the authentication, this gets fired
public class JwtAuthenticationEntryPoint extends Http403ForbiddenEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
			throws IOException {

		HttpResponse httpReponse = new HttpResponse(FORBIDDEN.value(), FORBIDDEN,
				FORBIDDEN.getReasonPhrase().toUpperCase(), FORBIDDEN_MESSAGE);
		response.setContentType(APPLICATION_JSON_VALUE);
		response.setStatus(FORBIDDEN.value());
		OutputStream outputStream = response.getOutputStream(); // Returns a ServletOutputStream suitable for writing
																// binary data in the response.
		ObjectMapper mapper = new ObjectMapper();
		mapper.writeValue(outputStream, httpReponse);
		outputStream.flush();
	}

}
