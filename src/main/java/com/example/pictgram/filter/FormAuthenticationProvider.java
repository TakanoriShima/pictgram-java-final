package com.example.pictgram.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.example.pictgram.entity.User;
import com.example.pictgram.repository.UserRepository;

@Configuration
public class FormAuthenticationProvider implements AuthenticationProvider {

	protected static Logger log = LoggerFactory.getLogger(FormAuthenticationProvider.class);

	@Autowired
	private UserRepository repository;

	@Override
	public Authentication authenticate(Authentication auth) throws AuthenticationException {
		String name = auth.getName();
		String password = auth.getCredentials().toString();

		log.debug("name={}", name);
		log.debug("暗号前password={}", password);

		if ("".equals(name) || "".equals(password)) {
			throw new AuthenticationCredentialsNotFoundException("ログイン情報に不備があります。");
		}

		User entity = repository.findByUsername(name);
		if (entity == null) {
			throw new AuthenticationCredentialsNotFoundException("ログイン情報が存在しません。");
		}

		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

		if (encoder.matches(password, entity.getPassword())) {
			return new UsernamePasswordAuthenticationToken(entity, password, entity.getAuthorities());
		}

		throw new AuthenticationCredentialsNotFoundException("basic auth error");

	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
}