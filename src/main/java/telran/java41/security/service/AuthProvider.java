package telran.java41.security.service;

import javax.security.auth.login.CredentialExpiredException;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import telran.java41.accounting.dao.UserAccountRepository;
import telran.java41.accounting.model.UserAccount;

@Component
@AllArgsConstructor
public class AuthProvider implements AuthenticationProvider {

	UserDetailServiceImpl userDetailService;
	UserAccountRepository userAccountRepository;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UserAccount userAccount = userAccountRepository.findById(authentication.getName())
				.orElseThrow(() -> new UsernameNotFoundException(authentication.getName()));
		if (!PasswordNonExpiredCheck.check(userAccount)) {
			System.out.println("auth check");
//			throw new CredentialExpiredException(); //FIXME
		}
		return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(),
				authentication.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}
