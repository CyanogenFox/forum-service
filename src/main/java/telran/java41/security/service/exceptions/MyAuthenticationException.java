package telran.java41.security.service.exceptions;

import org.springframework.security.core.AuthenticationException;

public class MyAuthenticationException extends AuthenticationException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 60565738366722296L;

	public MyAuthenticationException(String msg) {
		super(msg);
		// TODO Auto-generated constructor stub
	}

}
