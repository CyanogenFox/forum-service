package telran.java41.security.handlers;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Component
public class LoginFailureDuePasswordExpiredEvent implements AuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		System.out.println("failure test");

		if (exception.getClass().equals(BadCredentialsException.class)) {
			System.out.println("fuuuu");
			response.sendRedirect("/account/password");
		}
	}

}

//@Component
//public class LoginFailureDuePasswordExpiredEvent extends SimpleUrlAuthenticationFailureHandler
//		implements AuthenticationFailureHandler {
//
//	@Override
//	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
//			AuthenticationException exception) throws IOException, ServletException {
//		System.out.println("failure test");
//
//		setUseForward(true);
//		if (exception.getClass().equals(BadCredentialsException.class)) {
//			System.out.println("fuuuu");
//			setDefaultFailureUrl("/account/password");
//		}
//		super.onAuthenticationFailure(request, response, exception);
//	}
//
//}
