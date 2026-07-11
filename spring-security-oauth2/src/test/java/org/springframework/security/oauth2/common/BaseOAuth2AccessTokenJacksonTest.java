/*
 * Copyright 2006-2010 the original author or authors.
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
package org.springframework.security.oauth2.common;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.ExpectedException;

/**
 * Base class for testing Jackson serialization and deserialization of {@link OAuth2AccessToken}.
 *
 * <p>
 * Previously this class froze the clock with PowerMock's {@code mockStatic(System.class)}; PowerMock cannot
 * run on modern JVMs, so instead the mocked expiration {@link Date} answers
 * {@code System.currentTimeMillis() + 10500} at call time. The serializer reads the clock immediately before
 * the expiration, so {@code expires_in} is deterministically 10 (the 500ms slack absorbs the time between the
 * two reads); deserialization tests must compare expirations with a small tolerance instead of exact equality.
 * </p>
 *
 * @author Rob Winch
 */
abstract class BaseOAuth2AccessTokenJacksonTest {
	protected static final String ACCESS_TOKEN_EMPTYSCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"\"}";

	protected static final String ACCESS_TOKEN_BROKENEXPIRES = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":\"10\",\"scope\":\"\"}";

	protected static final String ACCESS_TOKEN_MULTISCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"read write\"}";

	protected static final String ACCESS_TOKEN_ARRAYSCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":[\"read\",\"write\"]}";

	protected static final String ACCESS_TOKEN_NOSCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10}";

	protected static final String ACCESS_TOKEN_NOREFRESH = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"expires_in\":10}";

	protected static final String ACCESS_TOKEN_SINGLESCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"write\"}";

	protected static final String ACCESS_TOKEN_ADDITIONAL_INFO = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"one\":\"two\",\"three\":4,\"five\":{\"six\":7}}";

	protected static final String ACCESS_TOKEN_ZERO_EXPIRES = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"expires_in\":0}";

	/**
	 * Maximum drift allowed when comparing an expected expiration (clock + 10500ms) with an expiration
	 * reconstructed from {@code expires_in:10} (clock + 10000ms).
	 */
	protected static final long EXPIRATION_TOLERANCE_MILLIS = 2000;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	protected Date expiration;

	protected DefaultOAuth2AccessToken accessToken;

	protected Map<String, Object> additionalInformation;

	public BaseOAuth2AccessTokenJacksonTest() {
		super();
	}

	@Before
	public void setUp() {
		expiration = mock(Date.class);
		when(expiration.before(any(Date.class))).thenReturn(false);
		when(expiration.getTime()).thenAnswer(invocation -> System.currentTimeMillis() + 10500L);

		accessToken = new DefaultOAuth2AccessToken("token-value");
		accessToken.setExpiration(expiration);
		DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken("refresh-value");
		accessToken.setRefreshToken(refreshToken);
		Set<String> scope = new TreeSet<String>();
		scope.add("read");
		scope.add("write");
		accessToken.setScope(scope);
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		map.put("one", "two");
		map.put("three", 4);
		map.put("five", Collections.singletonMap("six", 7));
		additionalInformation = map;
	}
}
