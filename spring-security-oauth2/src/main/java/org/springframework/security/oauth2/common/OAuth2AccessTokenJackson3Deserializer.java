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

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.springframework.security.oauth2.common.util.OAuth2Utils;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.exc.InputCoercionException;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

/**
 * Jackson 3 port of {@link OAuth2AccessTokenJackson2Deserializer}: deserializes the RFC 6749 token response
 * format into an {@link org.springframework.security.oauth2.common.OAuth2AccessToken}.
 *
 * <p>
 * The expected format of the access token is defined by <a
 * href="https://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-5.1">Successful Response</a>.
 * </p>
 *
 * @see OAuth2AccessTokenJackson3Serializer
 */
public final class OAuth2AccessTokenJackson3Deserializer extends StdDeserializer<OAuth2AccessToken> {

	public OAuth2AccessTokenJackson3Deserializer() {
		super(OAuth2AccessToken.class);
	}

	@Override
	public OAuth2AccessToken deserialize(JsonParser jp, DeserializationContext ctxt) {

		String tokenValue = null;
		String tokenType = null;
		String refreshToken = null;
		Long expiresIn = null;
		Set<String> scope = null;
		Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();

		while (jp.nextToken() != JsonToken.END_OBJECT) {
			String name = jp.currentName();
			jp.nextToken();
			if (OAuth2AccessToken.ACCESS_TOKEN.equals(name)) {
				tokenValue = jp.getString();
			}
			else if (OAuth2AccessToken.TOKEN_TYPE.equals(name)) {
				tokenType = jp.getString();
			}
			else if (OAuth2AccessToken.REFRESH_TOKEN.equals(name)) {
				refreshToken = jp.getString();
			}
			else if (OAuth2AccessToken.EXPIRES_IN.equals(name)) {
				try {
					expiresIn = jp.getLongValue();
				} catch (InputCoercionException e) {
					expiresIn = Long.valueOf(jp.getString());
				}
			}
			else if (OAuth2AccessToken.SCOPE.equals(name)) {
				scope = parseScope(jp);
			} else {
				additionalInformation.put(name, jp.readValueAs(Object.class));
			}
		}

		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(tokenValue);
		accessToken.setTokenType(tokenType);
		if (expiresIn != null && expiresIn != 0) {
			accessToken.setExpiration(new Date(System.currentTimeMillis() + (expiresIn * 1000)));
		}
		if (refreshToken != null) {
			accessToken.setRefreshToken(new DefaultOAuth2RefreshToken(refreshToken));
		}
		accessToken.setScope(scope);
		accessToken.setAdditionalInformation(additionalInformation);

		return accessToken;
	}

	private Set<String> parseScope(JsonParser jp) {
		Set<String> scope;
		if (jp.currentToken() == JsonToken.START_ARRAY) {
			scope = new TreeSet<String>();
			while (jp.nextToken() != JsonToken.END_ARRAY) {
				scope.add(jp.getValueAsString());
			}
		} else {
			String text = jp.getString();
			scope = OAuth2Utils.parseParameterList(text);
		}
		return scope;
	}
}
