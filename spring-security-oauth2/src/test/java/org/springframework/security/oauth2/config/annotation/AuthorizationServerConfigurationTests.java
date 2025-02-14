/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.config.annotation;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.Mockito;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.TestingAuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.config.authentication.AuthenticationManagerBeanDefinitionParser;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.CheckTokenEndpoint;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import jakarta.servlet.Filter;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.sql.DataSource;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * @author Dave Syer
 * 
 */
@RunWith(Parameterized.class)
public class AuthorizationServerConfigurationTests {

	private AnnotationConfigWebApplicationContext context;

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private Class<?>[] resources;

	@Parameters
	public static List<Object[]> parameters() {
		return Arrays.asList( // @formatter:off
				new Object[] { BeanCreationException.class, new Class<?>[] { AuthorizationServerUnconfigured.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerCycle.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerVanilla.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerDisableApproval.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerExtras.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerJdbc.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerEncoder.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerJwt.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerJwtCustomSigner.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerWithTokenServices.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerApproval.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerExceptionTranslator.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerCustomClientDetails.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerAllowsSpecificRequestMethods.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerAllowsOnlyPost.class } },
				new Object[] { BeanCreationException.class, new Class<?>[] { AuthorizationServerTypes.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerCustomGranter.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerSslEnabled.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerCustomRedirectResolver.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerDefaultRedirectResolver.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerCustomAuthenticationProvidersOnTokenEndpoint.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerDefaultAuthenticationProviderOnTokenEndpoint.class } },
				new Object[] { null, new Class<?>[] { AuthorizationServerCustomAuthenticationEventPublisher.class } }
		// @formatter:on
		);
	}

	public AuthorizationServerConfigurationTests(Class<? extends Exception> error, Class<?>... resource) {
		if (error != null) {
			expected.expect(error);
		}
		this.resources = resource;
		context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(resource);
	}

	@After
	public void close() {
		if (context != null) {
			context.close();
		}
	}

	@Test
	public void testDefaults() {
		context.refresh();
		assertTrue(context.containsBeanDefinition("authorizationEndpoint"));
		assertNotNull(context.getBean("authorizationEndpoint", AuthorizationEndpoint.class));
		for (Class<?> resource : resources) {
			if (Runnable.class.isAssignableFrom(resource)) {
				((Runnable) context.getBean(resource)).run();
			}
		}
	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerUnconfigured {
	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerVanilla extends AuthorizationServerConfigurerAdapter implements Runnable {
		@Autowired
		private AuthorizationEndpoint endpoint;

		@Autowired
		private ClientDetailsService clientDetailsService;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client")
					.authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
					.authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT").scopes("read", "write", "trust")
					.accessTokenValiditySeconds(60).additionalInformation("foo:bar", "spam:bucket", "crap", "bad:");
			// @formatter:on
		}

		@Override
		public void run() {
			// With no explicit approval store we still expect to see scopes in
			// the user approval model
			UserApprovalHandler handler = (UserApprovalHandler) ReflectionTestUtils.getField(endpoint,
					"userApprovalHandler");
			AuthorizationRequest authorizationRequest = new AuthorizationRequest();
			authorizationRequest.setScope(Arrays.asList("read"));
			Map<String, Object> request = handler.getUserApprovalRequest(authorizationRequest,
					new UsernamePasswordAuthenticationToken("user", "password"));
			assertTrue(request.containsKey("scopes"));

			Map<String, Object> information = clientDetailsService.loadClientByClientId("my-trusted-client")
					.getAdditionalInformation();

			assertTrue(information.containsKey("foo"));
			assertTrue(information.get("foo").equals("bar"));
			assertTrue(information.get("spam").equals("bucket"));
			assertTrue(information.get("crap") == null);
			assertTrue(information.get("bad").equals(""));
		}
	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerCycle extends AuthorizationServerConfigurerAdapter implements Runnable {
		@Autowired
		private AuthorizationServerTokenServices tokenServices;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenServices(tokenServices); // cycle can lead to null
													// here
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client").authorizedGrantTypes("password");
			// @formatter:on
		}

		@Override
		public void run() {
			assertNotNull(tokenServices);
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerDisableApproval extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		@Autowired
		private AuthorizationEndpoint endpoint;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client").authorizedGrantTypes("password");
			// @formatter:on
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.approvalStoreDisabled();
		}

		@Override
		public void run() {
			// There should be no scopes in the approval model
			UserApprovalHandler handler = (UserApprovalHandler) ReflectionTestUtils.getField(endpoint,
					"userApprovalHandler");
			AuthorizationRequest authorizationRequest = new AuthorizationRequest();
			authorizationRequest.setScope(Arrays.asList("read"));
			Map<String, Object> request = handler.getUserApprovalRequest(authorizationRequest,
					new UsernamePasswordAuthenticationToken("user", "password"));
			assertFalse(request.containsKey("scopes"));
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerAllowsSpecificRequestMethods extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		@Autowired
		private TokenEndpoint endpoint;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client").authorizedGrantTypes("password");
			// @formatter:on
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.PUT);
		}

		@Override
		public void run() {
			@SuppressWarnings("unchecked")
			Set<HttpMethod> allowedRequestMethods = (Set<HttpMethod>) ReflectionTestUtils.getField(endpoint,
					"allowedRequestMethods");
			assertTrue(allowedRequestMethods.contains(HttpMethod.GET));
			assertTrue(allowedRequestMethods.contains(HttpMethod.PUT));
			assertFalse(allowedRequestMethods.contains(HttpMethod.POST));
		}
	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerAllowsOnlyPost extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		@Autowired
		private TokenEndpoint endpoint;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client").authorizedGrantTypes("password");
			// @formatter:on
		}

		@Override
		public void run() {
			@SuppressWarnings("unchecked")
			Set<HttpMethod> allowedRequestMethods = (Set<HttpMethod>) ReflectionTestUtils.getField(endpoint,
					"allowedRequestMethods");
			assertFalse(allowedRequestMethods.contains(HttpMethod.GET));
			assertTrue(allowedRequestMethods.contains(HttpMethod.POST));
		}
	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerExtras extends AuthorizationServerConfigurerAdapter implements Runnable {

		private TokenStore tokenStore = new InMemoryTokenStore();

		@Autowired
		private ApplicationContext context;

		@Bean
		public DefaultUserApprovalHandler userApprovalHandler() {
			return new DefaultUserApprovalHandler();
		}

		@Bean
		public TokenApprovalStore approvalStore() {
			return new TokenApprovalStore();
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenStore(tokenStore).approvalStore(approvalStore()).userApprovalHandler(userApprovalHandler())
					.addInterceptor(new HandlerInterceptor() {
					});
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer.realm("oauth/sparklr");
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client")
					.authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
					.authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT").scopes("read", "write", "trust")
					.accessTokenValiditySeconds(60);
			// @formatter:on
		}

		@Override
		public void run() {
			assertNotNull(context.getBean("clientDetailsService", ClientDetailsService.class)
					.loadClientByClientId("my-trusted-client"));
			assertNotNull(
					ReflectionTestUtils.getField(context.getBean(AuthorizationEndpoint.class), "userApprovalHandler"));
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerJdbc extends AuthorizationServerConfigurerAdapter {

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenStore(new JdbcTokenStore(dataSource()));
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.jdbc(dataSource()).withClient("my-trusted-client").authorizedGrantTypes("password");
			// @formatter:on
		}

		@Bean
		public DataSource dataSource() {
			return Mockito.mock(DataSource.class);
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerEncoder extends AuthorizationServerConfigurerAdapter {

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client").secret(new BCryptPasswordEncoder().encode("secret"))
					.authorizedGrantTypes("client_credentials");
			// @formatter:on
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer.passwordEncoder(new BCryptPasswordEncoder());
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerJwt extends AuthorizationServerConfigurerAdapter {

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtTokenEnhancer());
		}

		@Bean
		public TokenStore tokenStore() {
			return new JwtTokenStore(jwtTokenEnhancer());
		}

		@Bean
		protected JwtAccessTokenConverter jwtTokenEnhancer() {
			return new JwtAccessTokenConverter();
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client").authorizedGrantTypes("password");
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerJwtCustomSigner extends AuthorizationServerConfigurerAdapter {

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtTokenEnhancer());
		}

		@Bean
		public TokenStore tokenStore() {
			return new JwtTokenStore(jwtTokenEnhancer());
		}

		@Bean
		protected JwtAccessTokenConverter jwtTokenEnhancer() {
			JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
			MacSigner verifier = new MacSigner("foobar");
			converter.setSigner(verifier);
			converter.setVerifier(verifier);
			return converter;
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client").authorizedGrantTypes("password");
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerWithTokenServices extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		@Autowired
		private ClientDetailsService clientDetailsService;

		@Autowired
		private ApplicationContext context;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenServices(tokenServices()).tokenStore(tokenStore());
		}

		@Bean
		public DefaultTokenServices tokenServices() {
			DefaultTokenServices tokenServices = new DefaultTokenServices();
			tokenServices.setTokenStore(tokenStore());
			tokenServices.setAccessTokenValiditySeconds(300);
			tokenServices.setRefreshTokenValiditySeconds(30000);
			tokenServices.setClientDetailsService(clientDetailsService);
			return tokenServices;
		}

		@Bean
		public TokenStore tokenStore() {
			return new InMemoryTokenStore();
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client").authorizedGrantTypes("password");
			// @formatter:on
		}

		@Override
		public void run() {
			assertNotNull(
					ReflectionTestUtils.getField(context.getBean(CheckTokenEndpoint.class), "accessTokenConverter"));
		}
	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerApproval extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		private TokenStore tokenStore = new InMemoryTokenStore();

		@Autowired
		private ApplicationContext context;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenStore(tokenStore);
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client").authorizedGrantTypes("password");
			// @formatter:on
		}

		@Override
		public void run() {
			assertNotNull(
					ReflectionTestUtils.getField(context.getBean(AuthorizationEndpoint.class), "userApprovalHandler"));
		}

	}

	@EnableWebSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerCustomRedirectResolver extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		@Autowired
		private ApplicationContext context;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.redirectResolver(new CustomRedirectResolver());
		}

		@Override
		public void run() {
			RedirectResolver resolver = (RedirectResolver) ReflectionTestUtils.getField(context.getBean(AuthorizationEndpoint.class), "redirectResolver");

			assertNotNull(resolver);
			assertTrue(resolver instanceof CustomRedirectResolver);
		}

		static class CustomRedirectResolver implements RedirectResolver {
			@Override
			public String resolveRedirect(final String requestedRedirect, final ClientDetails client) throws OAuth2Exception {
				return "go/here";
			}
		}
	}

	@EnableWebSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerDefaultRedirectResolver extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		@Autowired
		private ApplicationContext context;

		@Override
		public void run() {
			assertNotNull(
					ReflectionTestUtils.getField(context.getBean(AuthorizationEndpoint.class), "redirectResolver"));
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerExceptionTranslator extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		private TokenStore tokenStore = new InMemoryTokenStore();

		@Autowired
		private ApplicationContext context;

		private DefaultWebResponseExceptionTranslator exceptionTranslator = new DefaultWebResponseExceptionTranslator();

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenStore(tokenStore).exceptionTranslator(exceptionTranslator);
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.inMemory().withClient("my-trusted-client").authorizedGrantTypes("password");
			// @formatter:on
		}

		@Override
		public void run() {
			assertEquals(exceptionTranslator, ReflectionTestUtils.getField(context.getBean(AuthorizationEndpoint.class),
					"providerExceptionHandler"));
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerCustomGranter extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		@Autowired
		private ApplicationContext context;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenGranter(
					new ClientCredentialsTokenGranter(endpoints.getDefaultAuthorizationServerTokenServices(),
							endpoints.getClientDetailsService(), endpoints.getOAuth2RequestFactory()));
		}

		@Override
		public void run() {
			assertTrue(ReflectionTestUtils.getField(context.getBean(TokenEndpoint.class),
					"tokenGranter") instanceof ClientCredentialsTokenGranter);
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	// Stuff that can't be autowired
	protected static class AuthorizationServerTypes extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthorizationServerTokenServices tokenServices;

		@Autowired
		private ClientDetailsService clientDetailsService;

		@Autowired
		private OAuth2RequestFactory requestFactory;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			assertTrue(tokenServices!=null && clientDetailsService!=null && requestFactory!=null);
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerCustomClientDetails extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		@Autowired
		private ApplicationContext context;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.withClientDetails(new InMemoryClientDetailsService());
		}

		@Override
		public void run() {
			assertNotNull(context.getBean(ClientDetailsService.class));
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerCustomUserDetails extends AuthorizationServerConfigurerAdapter
			implements Runnable {

		@Autowired
		private ApplicationContext context;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.userDetailsService(userDetailsService());
		}

		private UserDetailsService userDetailsService() {
			return new UserDetailsService() {

				@Override
				public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
					return new User(username, "", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
				}
			};
		}

		@Override
		public void run() {
			assertNotNull(context.getBean(UserDetailsService.class));
		}

	}

	// gh-638
	@EnableWebSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerSslEnabled extends AuthorizationServerConfigurerAdapter {

		@Override
		public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
			security.sslOnly();
		}
	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerCustomAuthenticationProvidersOnTokenEndpoint extends
			AuthorizationServerConfigurerAdapter implements Runnable {

		@Autowired
		private ApplicationContext context; 

		@Override
		public void configure(AuthorizationServerSecurityConfigurer security)
				throws Exception {
			security.addAuthenticationProvider(new AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider());
			security.addAuthenticationProvider(new TestingAuthenticationProvider());
		}

		@Override
		public void run() { 
			FilterChainProxy springSecurityFilterChain = context.getBean(FilterChainProxy.class);
			List<Filter> filters = springSecurityFilterChain.getFilters("/oauth/token");
			BasicAuthenticationFilter basicAuthenticationFilter = null;
			for (Filter filter : filters) {
				if (filter instanceof BasicAuthenticationFilter) {
					basicAuthenticationFilter = (BasicAuthenticationFilter) filter;
					break;
				}
			}

			ProviderManager authenticationManager = (ProviderManager) ReflectionTestUtils.getField(basicAuthenticationFilter, "authenticationManager");
			boolean nullAuthenticationProviderFound = false;
			boolean testingAuthenticationProviderFound = false;
			boolean anonymousAuthenticationProviderFound = false;
			for (AuthenticationProvider provider : authenticationManager.getProviders()) {
				if (provider instanceof AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider) {
					nullAuthenticationProviderFound = true;
				} else if (provider instanceof TestingAuthenticationProvider) {
					testingAuthenticationProviderFound = true;
				} else if (provider instanceof AnonymousAuthenticationProvider) {
					anonymousAuthenticationProviderFound = true;
				}
			}

			assertEquals(3, authenticationManager.getProviders().size());
			assertTrue(testingAuthenticationProviderFound);
			assertTrue(anonymousAuthenticationProviderFound);
			assertTrue(nullAuthenticationProviderFound);
		}
	}	

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerDefaultAuthenticationProviderOnTokenEndpoint extends
			AuthorizationServerConfigurerAdapter implements Runnable {

		@Autowired
		private ApplicationContext context; 

		@Override
		public void run() { 
			FilterChainProxy springSecurityFilterChain = context.getBean(FilterChainProxy.class);
			List<Filter> filters = springSecurityFilterChain.getFilters("/oauth/token");
			BasicAuthenticationFilter basicAuthenticationFilter = null;
			for (Filter filter : filters) {
				if (filter instanceof BasicAuthenticationFilter) {
					basicAuthenticationFilter = (BasicAuthenticationFilter) filter;
					break;
				}
			}

			ProviderManager authenticationManager = (ProviderManager) ReflectionTestUtils.getField(basicAuthenticationFilter, "authenticationManager");
			boolean anonymousAuthenticationProviderFound = false;
			boolean daoAuthenticationProviderFound = false;

			for (AuthenticationProvider provider : authenticationManager.getProviders()) {
				if (provider instanceof DaoAuthenticationProvider) {
					daoAuthenticationProviderFound = true;
				} else if (provider instanceof AnonymousAuthenticationProvider) {
					anonymousAuthenticationProviderFound = true;
				}
			}

			assertEquals(2, authenticationManager.getProviders().size());
			assertTrue(anonymousAuthenticationProviderFound);
			assertTrue(daoAuthenticationProviderFound);
		}
	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerCustomAuthenticationEventPublisher extends
			AuthorizationServerConfigurerAdapter implements Runnable {

		@Autowired
		private ApplicationContext context;
		private AuthenticationEventPublisher defaultAuthenticationEventPublisher = new DefaultAuthenticationEventPublisher();

		@Override
		public void configure(AuthorizationServerSecurityConfigurer security)
				throws Exception {
			security.authenticationEventPublisher(defaultAuthenticationEventPublisher);
		}

		@Override
		public void run() {
			FilterChainProxy springSecurityFilterChain = context.getBean(FilterChainProxy.class);
			List<Filter> filters = springSecurityFilterChain.getFilters("/oauth/token");
			BasicAuthenticationFilter basicAuthenticationFilter = null;
			for (Filter filter : filters) {
				if (filter instanceof BasicAuthenticationFilter) {
					basicAuthenticationFilter = (BasicAuthenticationFilter) filter;
					break;
				}
			}
			
			AuthenticationManager authenticationManager = (AuthenticationManager) ReflectionTestUtils.
					getField(basicAuthenticationFilter, "authenticationManager");
			AuthenticationEventPublisher authenticationEventPublisher = (AuthenticationEventPublisher) ReflectionTestUtils.
					getField(authenticationManager, "eventPublisher");
			
			assertTrue(authenticationEventPublisher == defaultAuthenticationEventPublisher);
		}
	}
}
