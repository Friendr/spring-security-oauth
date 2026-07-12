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
import java.util.Map;
import java.util.Set;

import org.springframework.util.Assert;

import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

/**
 * Jackson 3 port of {@link OAuth2AccessTokenJackson2Serializer}: serializes an
 * {@link org.springframework.security.oauth2.common.OAuth2AccessToken} in the RFC 6749 token response format.
 *
 * The expected format of the access token is defined by <a href="https://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-5.1">Successful Response</a>.
 *
 * @see OAuth2AccessTokenJackson3Deserializer
 */
public final class OAuth2AccessTokenJackson3Serializer extends StdSerializer<OAuth2AccessToken> {

	public OAuth2AccessTokenJackson3Serializer() {
		super(OAuth2AccessToken.class);
	}

	@Override
	public void serialize(OAuth2AccessToken token, JsonGenerator jgen, SerializationContext ctxt) {
		jgen.writeStartObject();
		jgen.writeStringProperty(OAuth2AccessToken.ACCESS_TOKEN, token.getValue());
		jgen.writeStringProperty(OAuth2AccessToken.TOKEN_TYPE, token.getTokenType());
		OAuth2RefreshToken refreshToken = token.getRefreshToken();
		if (refreshToken != null) {
			jgen.writeStringProperty(OAuth2AccessToken.REFRESH_TOKEN, refreshToken.getValue());
		}
		Date expiration = token.getExpiration();
		if (expiration != null) {
			long now = System.currentTimeMillis();
			jgen.writeNumberProperty(OAuth2AccessToken.EXPIRES_IN, (expiration.getTime() - now) / 1000);
		}
		Set<String> scope = token.getScope();
		if (scope != null && !scope.isEmpty()) {
			StringBuffer scopes = new StringBuffer();
			for (String s : scope) {
				Assert.hasLength(s, "Scopes cannot be null or empty. Got " + scope + "");
				scopes.append(s);
				scopes.append(" ");
			}
			jgen.writeStringProperty(OAuth2AccessToken.SCOPE, scopes.substring(0, scopes.length() - 1));
		}
		Map<String, Object> additionalInformation = token.getAdditionalInformation();
		for (String key : additionalInformation.keySet()) {
			jgen.writePOJOProperty(key, additionalInformation.get(key));
		}
		jgen.writeEndObject();
	}
}
