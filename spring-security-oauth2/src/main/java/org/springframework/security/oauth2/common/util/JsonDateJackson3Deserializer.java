/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.common.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import tools.jackson.core.JsonParser;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ValueDeserializer;

/**
 * Jackson 3 port of {@link JsonDateDeserializer}: deserializes ISO-format timestamps into date instances.
 */
public class JsonDateJackson3Deserializer extends ValueDeserializer<Date> {

	private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

	@Override
	public Date deserialize(JsonParser parser, DeserializationContext context) {
		try {
			synchronized (dateFormat) {
				return dateFormat.parse(parser.getString());
			}
		}
		catch (ParseException e) {
			throw new StreamReadException(parser, "Could not parse date", e);
		}
	}
}
