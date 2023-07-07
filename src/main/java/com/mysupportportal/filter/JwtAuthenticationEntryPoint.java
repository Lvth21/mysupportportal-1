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
//handler for when the authentication fail:
@Component // whenever the user fail the authentication, this gets fired
public class JwtAuthenticationEntryPoint extends Http403ForbiddenEntryPoint {
	/*
	 * The AuthenticationEntryPoint interface is part of the Spring Security
	 * framework and it provides a way to handle unauthenticated requests. When an
	 * unauthenticated request is made to a protected resource, the commence()
	 * method of the AuthenticationEntryPoint is called.
	 * 
	 * In summary, this class is an extension of the Http403ForbiddenEntryPoint
	 * class and is responsible for handling authentication failures. When an
	 * authentication failure occurs, it sends a JSON response with a "FORBIDDEN"
	 * status and a message indicating that the user is not authorized to access the
	 * resource.
	 * 
	 * 
	 * By extending the class and overriding the method, you can change the default
	 * behavior of the class to fit the needs of your application.
	 */

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
		/*
		 * mapper is an instance of the ObjectMapper class, which is a part of the
		 * Jackson library. The ObjectMapper class is used to convert Java objects to
		 * JSON and vice versa. The writeValue method is used to serialize a Java object
		 * and write it to an output source, in this case the outputStream.
		 * 
		 * The outputStream is obtained from the response object, which is an instance
		 * of the HttpServletResponse class, and it represents the HTTP response that
		 * will be sent to the client. The writeValue method writes the JSON
		 * representation of the httpResponse object to the outputStream, so that it can
		 * be sent to the client as part of the response.
		 */
		outputStream.flush();
	}

	/*
	 * 
	 * The class overrides the commence method, which is called when an
	 * authentication failure occurs. This method is called when a user tries to
	 * access a protected resource without the necessary authentication.
	 * 
	 * The method starts by creating a new instance of the HttpResponse class,
	 * passing in some parameters such as the status code, the status and the
	 * message. Then it sets the content type of the response to
	 * APPLICATION_JSON_VALUE, the HTTP status to FORBIDDEN using the setStatus
	 * method on the response object, and then it gets the output stream from the
	 * response and creates a new instance of the ObjectMapper class, this class is
	 * used to convert Java objects to JSON and vice versa.
	 * 
	 * Finally, it calls the writeValue method on the mapper object, passing in the
	 * output stream and the httpResponse object, this writes the JSON
	 * representation of the HttpResponse object
	 * 
	 */
}
