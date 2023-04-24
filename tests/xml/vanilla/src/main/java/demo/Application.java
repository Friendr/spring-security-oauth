package demo;

import jakarta.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.endpoint.WhitelabelApprovalEndpoint;
import org.springframework.security.oauth2.provider.endpoint.WhitelabelErrorEndpoint;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@ComponentScan
@EnableAutoConfiguration
@RestController
@ImportResource("classpath:/context.xml")
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@RequestMapping("/")
	public String home() {
		return "Hello World";
	}

	@Configuration
	protected static class OAuth2Config {

		@Autowired
		private ClientDetailsService clientDetailsService;

		@Bean
		public DefaultTokenServices tokenServices() {
			DefaultTokenServices services = new DefaultTokenServices();
			services.setClientDetailsService(clientDetailsService);
			services.setSupportRefreshToken(true);
			services.setTokenStore(new InMemoryTokenStore());
			return services;
		}

		@Bean
		public WhitelabelErrorEndpoint oauth2ErrorEndpoint() {
			return new WhitelabelErrorEndpoint();
		}

		@Bean
		public WhitelabelApprovalEndpoint oauth2ApprovalEndpoint() {
			return new WhitelabelApprovalEndpoint();
		}

	}

	@Configuration
	protected static class ResourceServer {
		
		@Autowired
		@Qualifier("resourceFilter")
		private Filter resourceFilter;

		@Bean
		public FilterRegistrationBean<Filter> resourceFilterRegistration() {
			FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>();
			bean.setFilter(resourceFilter);
			bean.setEnabled(false);
			return bean;
		}

		@Bean
		public SecurityFilterChain resourceSecurityFilterChain(HttpSecurity http) throws Exception {
			return http
					.addFilterBefore(resourceFilter, AbstractPreAuthenticatedProcessingFilter.class)
					.securityMatcher(new NegatedRequestMatcher(new AntPathRequestMatcher("/oauth/**")))
					.authorizeRequests(authz -> authz
							.anyRequest().authenticated().expressionHandler(new OAuth2WebSecurityExpressionHandler())
					)
					.anonymous().disable()
					.csrf().disable()
					.exceptionHandling(exceptionHandling -> exceptionHandling
							.authenticationEntryPoint(new OAuth2AuthenticationEntryPoint())
							.accessDeniedHandler(new OAuth2AccessDeniedHandler())
					)
					.build();
		}

	}

	@Configuration
	protected static class TokenEndpointSecurity {

		@Autowired
		private ClientDetailsService clientDetailsService;

		@Bean
		protected UserDetailsService clientDetailsUserService() {
			return new ClientDetailsUserDetailsService(clientDetailsService);
		}

		@Order(Ordered.HIGHEST_PRECEDENCE)
		@Bean
		public SecurityFilterChain tokenSecurityFilterChain(HttpSecurity http) throws Exception {
			return http
					.anonymous().disable()
					.securityMatcher("/oauth/token")
					.authorizeRequests(authz -> authz
							.anyRequest().authenticated()
					)
					.httpBasic(httpBasic -> httpBasic
							.authenticationEntryPoint(authenticationEntryPoint())
					)
					.csrf(csrf -> csrf
							.requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/token")).disable()
					)
					.exceptionHandling(exceptionHandling -> exceptionHandling
							.accessDeniedHandler(accessDeniedHandler())
							.authenticationEntryPoint(authenticationEntryPoint())
					)
					.sessionManagement(sessionManagement -> sessionManagement
							.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					)
					.build();
		}

		@Bean
		protected AccessDeniedHandler accessDeniedHandler() {
			return new OAuth2AccessDeniedHandler();
		}

		@Bean
		protected AuthenticationEntryPoint authenticationEntryPoint() {
			OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();
			entryPoint.setTypeName("Basic");
			entryPoint.setRealmName("oauth2/client");
			return entryPoint;
		}

	}

}
