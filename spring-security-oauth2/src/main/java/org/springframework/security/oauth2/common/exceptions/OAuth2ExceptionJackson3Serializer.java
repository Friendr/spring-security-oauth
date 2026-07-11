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
package org.springframework.security.oauth2.common.exceptions;

import java.util.Map.Entry;

import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

/**
 * Jackson 3 port of {@link OAuth2ExceptionJackson2Serializer}: serializes {@link OAuth2Exception} in the
 * RFC 6749 error response format.
 */
public class OAuth2ExceptionJackson3Serializer extends StdSerializer<OAuth2Exception> {

	public OAuth2ExceptionJackson3Serializer() {
		super(OAuth2Exception.class);
	}

	@Override
	public void serialize(OAuth2Exception value, JsonGenerator jgen, SerializationContext ctxt) {
		jgen.writeStartObject();
		jgen.writeStringProperty("error", value.getOAuth2ErrorCode());
		jgen.writeStringProperty("error_description", value.getMessage());
		if (value.getAdditionalInformation() != null) {
			for (Entry<String, String> entry : value.getAdditionalInformation().entrySet()) {
				String key = entry.getKey();
				String add = entry.getValue();
				jgen.writeStringProperty(key, add);
			}
		}
		jgen.writeEndObject();
	}

}
