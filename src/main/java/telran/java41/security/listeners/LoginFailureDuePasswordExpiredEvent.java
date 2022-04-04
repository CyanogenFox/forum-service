package telran.java41.security.listeners;

import java.io.IOException;

import javax.security.auth.login.CredentialExpiredException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Component
public class LoginFailureDuePasswordExpiredEvent extends SimpleUrlAuthenticationFailureHandler
		implements AuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		System.out.println("failure test");

		setUseForward(true);
		if (exception.getClass().equals(CredentialExpiredException.class)) {
			System.out.println("fuuuu");
			setDefaultFailureUrl("/account/password");
		}
		super.onAuthenticationFailure(request, response, exception);
	}

}
