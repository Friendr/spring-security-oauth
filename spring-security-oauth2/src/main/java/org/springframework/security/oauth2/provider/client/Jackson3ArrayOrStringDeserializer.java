package org.springframework.security.oauth2.provider.client;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.util.StringUtils;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

/**
 * Jackson 3 port of {@link Jackson2ArrayOrStringDeserializer}: deserializes either a JSON array or a
 * comma/whitespace-delimited string into a {@code Set<String>}.
 */
public class Jackson3ArrayOrStringDeserializer extends StdDeserializer<Set<String>> {

	public Jackson3ArrayOrStringDeserializer() {
		super(Set.class);
	}

	@Override
	public Set<String> deserialize(JsonParser jp, DeserializationContext ctxt) {
		JsonToken token = jp.currentToken();
		if (token.isScalarValue()) {
			String list = jp.getString();
			list = list.replaceAll("\\s+", ",");
			return new LinkedHashSet<String>(Arrays.asList(StringUtils.commaDelimitedListToStringArray(list)));
		}
		return jp.readValueAs(new TypeReference<Set<String>>() {
		});
	}
}
