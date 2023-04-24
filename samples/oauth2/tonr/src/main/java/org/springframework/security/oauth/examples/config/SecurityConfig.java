package org.springframework.security.oauth.examples.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
		UserDetails user1 = User.withDefaultPasswordEncoder()
				.username("marissa")
				.password("wombat")
				.roles("USER")
				.build();
		UserDetails user2 = User.withDefaultPasswordEncoder()
				.username("sam")
				.password("kangaroo")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user1, user2);
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> web.ignoring().requestMatchers("/resources/**");
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
				.authorizeHttpRequests(authz -> authz
						.requestMatchers("/sparklr/**", "/facebook/**").hasRole("USER")
						.anyRequest().permitAll()
				)
				.logout(logout -> logout
						.logoutSuccessUrl("/login.jsp")
						.permitAll()
				)
				.formLogin(formLogin -> formLogin
						.loginProcessingUrl("/login")
						.loginPage("/login.jsp")
						.failureUrl("/login.jsp?authentication_error=true")
						.permitAll()
				)
				.build();
	}

}
