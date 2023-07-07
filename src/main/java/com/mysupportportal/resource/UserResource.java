package com.mysupportportal.resource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import static com.mysupportportal.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static com.mysupportportal.constant.FileConstant.*;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import javax.mail.MessagingException;

import com.mysupportportal.domain.User;
import com.mysupportportal.exception.ExceptionHandling;
import com.mysupportportal.exception.domain.EmailExistException;
import com.mysupportportal.exception.domain.UserNotFoundException;
import com.mysupportportal.exception.domain.UsernameExistException;
import com.mysupportportal.service.UserService;
import com.mysupportportal.utility.JWTTokenProvider;
import com.mysupportportal.domain.HttpResponse;
import com.mysupportportal.exception.domain.EmailNotFoundException;
import com.mysupportportal.exception.domain.NotAnImageFileException;
import com.mysupportportal.domain.UserPrincipal;

//@CrossOrigin(origins ="http://localhost:4200")  //can't do this way, cuz the jwtToken wouldnt be read
@RestController
@RequestMapping(path = { "/", "/user" })
public class UserResource extends ExceptionHandling {
	public static final String EMAIL_SENT = "An email with a new password was sent to: ";
	public static final String USER_DELETED_SUCCESSFULLY = "User deleted successfully";
	private UserService userService;
	/*
	 * The AuthenticationManager is an interface in the Spring Security framework
	 * that is responsible for authenticating a user. It is the main interface for
	 * authenticating a user in a Spring Security application.
	 * 
	 * It defines a single method, authenticate(Authentication), which takes an
	 * Authentication object as a parameter, and returns an authenticated
	 * Authentication object if the authentication is successful. The Authentication
	 * object contains the user's credentials (such as username and password) and is
	 * used to represent the user that is currently trying to authenticate.
	 * 
	 * In a typical Spring Security application, an instance of the
	 * AuthenticationManager interface is defined and configured in the
	 * application's security configuration. The implementation of the
	 * AuthenticationManager interface is responsible for checking the user's
	 * credentials against the application's security data store (such as a database
	 * or LDAP server) and determining whether the user should be granted access to
	 * the application.
	 * 
	 * In practice, the AuthenticationManager is responsible for verifying the
	 * user's credentials and returning an authenticated Authentication object. This
	 * object is then stored in the security context and can be used throughout the
	 * application to check if the user is authenticated and authorized to access
	 * certain resources
	 * 
	 * 
	 */
	private AuthenticationManager authenticationManager;
	private JWTTokenProvider jwtTokenProvider;

	@Autowired
	public UserResource(UserService userService, AuthenticationManager authenticationManager,
			JWTTokenProvider jwtTokenProvider) {
		super();
		this.userService = userService;
		this.authenticationManager = authenticationManager;
		this.jwtTokenProvider = jwtTokenProvider;
	}

	@PostMapping("/login")
	public ResponseEntity<User> login(@RequestBody User user) {
		authenticate(user.getUsername(), user.getPassword());
		User loginUser = userService.findUserByUsername(user.getUsername());
		UserPrincipal userPrincipal = new UserPrincipal(loginUser);
		HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
		return new ResponseEntity<>(loginUser, jwtHeader, OK);
	}

	@PostMapping("/register")
	public ResponseEntity<User> register(@RequestBody User user)
			throws UserNotFoundException, UsernameExistException, EmailExistException {

		User newUser = userService.register(user.getFirstName(), user.getLastName(), user.getUsername(),
				user.getEmail());

		return new ResponseEntity<>(newUser, OK);
	}

	@PostMapping("/add")
	public ResponseEntity<User> addNewUser(@RequestParam("firstName") String firstName,
			@RequestParam("lastName") String lastName, @RequestParam("username") String username,
			@RequestParam("email") String email, @RequestParam("role") String role,
			@RequestParam("isActive") String isActive, @RequestParam("isNonLocked") String isNonLocked,
			@RequestParam(value = "profileImage", required = false) MultipartFile profileImage)
			throws UserNotFoundException, UsernameExistException, EmailExistException, IOException,
			NotAnImageFileException {
		User newUser = userService.addNewUser(firstName, lastName, username, email, role,
				Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive), profileImage);
		return new ResponseEntity<>(newUser, OK);
	}

	@PostMapping("/update")
	public ResponseEntity<User> update(@RequestParam("currentUsername") String currentUsername,
			@RequestParam("firstName") String firstName, @RequestParam("lastName") String lastName,
			@RequestParam("username") String username, @RequestParam("email") String email,
			@RequestParam("role") String role, @RequestParam("isActive") String isActive,
			@RequestParam("isNonLocked") String isNonLocked,
			@RequestParam(value = "profileImage", required = false) MultipartFile profileImage)
			throws UserNotFoundException, UsernameExistException, EmailExistException, IOException,
			NotAnImageFileException {
		User updatedUser = userService.updateUser(currentUsername, firstName, lastName, username, email, role,
				Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive), profileImage);
		return new ResponseEntity<>(updatedUser, OK);
	}

	@GetMapping("/find/{username}")
	public ResponseEntity<User> getUser(@PathVariable("username") String username) {
		User user = userService.findUserByUsername(username);
		return new ResponseEntity<>(user, OK);
	}

	@GetMapping("/list")
	public ResponseEntity<List<User>> getAllUsers() {
		List<User> users = userService.getUsers();
		return new ResponseEntity<>(users, OK);
	}

	@GetMapping("/resetpassword/{email}")
	public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email)
			throws MessagingException, EmailNotFoundException {
		userService.resetPassword(email);
		return response(OK, EMAIL_SENT + email);
	}

	@DeleteMapping("/delete/{username}")
	@PreAuthorize("hasAnyAuthority('user:delete')")
	public ResponseEntity<HttpResponse> deleteUser(@PathVariable("username") String username) throws IOException {
		userService.deleteUser(username);
		return response(OK, USER_DELETED_SUCCESSFULLY);
	}

	@PostMapping("/updateProfileImage")
	public ResponseEntity<User> updateProfileImage(@RequestParam("username") String username,
			@RequestParam(value = "profileImage") MultipartFile profileImage) throws UserNotFoundException,
			UsernameExistException, EmailExistException, IOException, NotAnImageFileException {
		User user = userService.updateProfileImage(username, profileImage);
		return new ResponseEntity<>(user, OK);
	}

	@GetMapping(path = "/image/{username}/{fileName}", produces = IMAGE_JPEG_VALUE)
	public byte[] getProfileImage(@PathVariable("username") String username, @PathVariable("fileName") String fileName)
			throws IOException {
		return Files.readAllBytes(Paths.get(USER_FOLDER + username + FORWARD_SLASH + fileName));
	}

	@GetMapping(path = "/image/profile/{username}", produces = IMAGE_JPEG_VALUE)
	public byte[] getTempProfileImage(@PathVariable("username") String username) throws IOException {
		URL url = new URL(TEMP_PROFILE_IMAGE_BASE_URL + username);// the url is a big stream
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();// it is going to capture the data
																					// from the url in byte array
		try (InputStream inputStream = url.openStream()) {
			int bytesRead;
			byte[] chunk = new byte[1024];// we are going to read it in little pieces
			while ((bytesRead = inputStream.read(chunk)) > 0) {// when the bytes left to read are 0, stop.
				byteArrayOutputStream.write(chunk, 0, bytesRead);// writing the chunk, starting from 0, with these
																	// bytes.
			}
		}
		return byteArrayOutputStream.toByteArray();
	}

	private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {
		return new ResponseEntity<>(
				new HttpResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(), message),
				httpStatus);
	}
	/*
	 * The authenticate method of the authenticationManager is responsible for
	 * authenticating the user by validating the credentials passed in the
	 * UsernamePasswordAuthenticationToken object. If the credentials are valid, it
	 * will return an authenticated user, otherwise, it will throw an exception.
	 * 
	 * This method is most likely being used to authenticate the user credentials
	 * passed to the application, such as when a user is trying to log in. The
	 * UsernamePasswordAuthenticationToken is being used to check if the user
	 * entered the correct username and password.
	 * 
	 */

	private void authenticate(String username, String password) {
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
	}

	private HttpHeaders getJwtHeader(UserPrincipal user) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(user));
		return headers;
	}
}
