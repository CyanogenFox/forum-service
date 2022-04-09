package telran.java41.security.service;

import javax.security.auth.login.CredentialExpiredException;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import telran.java41.accounting.dao.UserAccountRepository;
import telran.java41.accounting.model.UserAccount;
import telran.java41.security.service.exceptions.MyAuthenticationException;

@Component
@AllArgsConstructor
public class AuthProvider implements AuthenticationProvider {

	UserDetailServiceImpl userDetailService;
	UserAccountRepository userAccountRepository;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UserAccount userAccount = userAccountRepository.findById(authentication.getName())
				.orElseThrow(() -> new UsernameNotFoundException(authentication.getName()));
		if (!BCrypt.checkpw(authentication.getCredentials().toString(), userAccount.getPassword()))
			throw new RuntimeException("Password is incorrect");
		if (!PasswordNonExpiredCheck.check(userAccount)) {
//			throw new BadCredentialsException("Password expired");
			throw new UsernameNotFoundException("aaa");
		}
		Authentication token = new UsernamePasswordAuthenticationToken(authentication.getName(),
				authentication.getCredentials().toString(), authentication.getAuthorities());
		return token;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}
