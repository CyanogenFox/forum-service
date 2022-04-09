package telran.java41.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import telran.java41.security.handlers.LoginFailureDuePasswordExpiredEvent;

@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AuthorizationConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	LoginFailureDuePasswordExpiredEvent loginFailureDuePasswordExpiredEvent;
	
	public AuthenticationFailureHandler authenticationFailureHandler() {
		return new LoginFailureDuePasswordExpiredEvent();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic();
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);// temp
		http.authorizeRequests().antMatchers(HttpMethod.POST, "/account/register/**").permitAll()
				.antMatchers("/forum/posts/**").permitAll().antMatchers("/account/user/*/role/*/**")
				.hasRole("ADMINISTRATOR").antMatchers(HttpMethod.PUT, "/account/user/{login}/**")
				.access("#login == authentication.name").antMatchers(HttpMethod.DELETE, "/account/user/{login}/**")
				.access("#login == authentication.name or hasRole('ADMINISTRATOR')")
				.antMatchers(HttpMethod.POST, "/forum/post/{author}/**").access("#author == authentication.name")
				.antMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}/**")
				.access("#author == authentication.name").antMatchers(HttpMethod.PUT, "/forum/post/{id}/**")
				.access("@customSecurity.checkPostAuthority(#id, authentication.name)")
				.antMatchers(HttpMethod.DELETE, "/forum/post/{id}/**")
				.access("@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')")
				.anyRequest().authenticated().and().formLogin()
				.failureHandler(loginFailureDuePasswordExpiredEvent).permitAll().and().logout().deleteCookies("JSESSIONID");
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

}
