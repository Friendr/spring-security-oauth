package org.springframework.security.oauth2.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.Approval.ApprovalStatus;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

/**
 * Verifies that the Jackson 3 (tools.jackson) dual annotations produce the same RFC 6749 wire format as the
 * Jackson 2 serializers, so that a Spring Boot 4 consumer (Jackson 3 HTTP converters) emits byte-identical
 * token endpoint responses.
 */
public class Jackson3WireFormatTests {

	private final tools.jackson.databind.json.JsonMapper jackson3 = tools.jackson.databind.json.JsonMapper.builder().build();

	private final com.fasterxml.jackson.databind.ObjectMapper jackson2 = new com.fasterxml.jackson.databind.ObjectMapper();

	@Test
	public void accessTokenWireFormatMatchesJackson2() throws Exception {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("token-value");
		token.setTokenType("bearer");
		token.setRefreshToken(new DefaultOAuth2RefreshToken("refresh-value"));
		token.setScope(OAuth2Utils.parseParameterList("read write"));
		Map<String, Object> additional = new LinkedHashMap<String, Object>();
		additional.put("anonymous_id", "abc123");
		additional.put("custom_number", 42);
		token.setAdditionalInformation(additional);
		// no expiration: expires_in depends on the clock, covered separately below

		String json2 = jackson2.writeValueAsString(token);
		String json3 = jackson3.writeValueAsString(token);

		assertEquals(json2, json3);
		assertEquals("{\"access_token\":\"token-value\",\"token_type\":\"bearer\","
				+ "\"refresh_token\":\"refresh-value\",\"scope\":\"read write\","
				+ "\"anonymous_id\":\"abc123\",\"custom_number\":42}", json3);
	}

	@Test
	public void accessTokenExpirationSerializedAsExpiresIn() {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("token-value");
		token.setExpiration(new Date(System.currentTimeMillis() + 3600 * 1000));

		String json3 = jackson3.writeValueAsString(token);

		// expires_in is computed from the wall clock; allow for scheduling delay
		assertTrue("expected expires_in close to 3600 in " + json3,
				json3.matches(".*\"expires_in\":(359[0-9]|3600).*"));
	}

	@Test
	public void accessTokenRoundTripsUnderJackson3() {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("token-value");
		token.setTokenType("bearer");
		token.setRefreshToken(new DefaultOAuth2RefreshToken("refresh-value"));
		token.setScope(OAuth2Utils.parseParameterList("read write"));
		token.setExpiration(new Date(System.currentTimeMillis() + 3600 * 1000));

		OAuth2AccessToken read = jackson3.readValue(jackson3.writeValueAsString(token), OAuth2AccessToken.class);

		assertEquals(token.getValue(), read.getValue());
		assertEquals(token.getTokenType(), read.getTokenType());
		assertEquals(token.getRefreshToken().getValue(), read.getRefreshToken().getValue());
		assertEquals(token.getScope(), read.getScope());
		assertTrue("expiration should survive the round trip", read.getExpiration() != null);
	}

	@Test
	public void scopeArrayFormReadUnderJackson3() {
		OAuth2AccessToken read = jackson3.readValue(
				"{\"access_token\":\"t\",\"token_type\":\"bearer\",\"scope\":[\"read\",\"write\"]}",
				OAuth2AccessToken.class);
		assertEquals(OAuth2Utils.parseParameterList("read write"), read.getScope());
	}

	@Test
	public void exceptionWireFormatMatchesJackson2() throws Exception {
		OAuth2Exception ex = new OAuth2Exception("some message");
		ex.addAdditionalInformation("locale", "en");

		String json2 = jackson2.writeValueAsString(ex);
		String json3 = jackson3.writeValueAsString(ex);

		assertEquals(json2, json3);
		assertEquals("{\"error\":\"invalid_request\",\"error_description\":\"some message\",\"locale\":\"en\"}",
				json3);
	}

	@Test
	public void exceptionDeserializedToSpecificSubclassUnderJackson3() {
		OAuth2Exception ex = jackson3.readValue(
				"{\"error\":\"invalid_client\",\"error_description\":\"bad client\"}", OAuth2Exception.class);
		assertTrue("expected InvalidClientException but got " + ex.getClass(), ex instanceof InvalidClientException);
		assertEquals("bad client", ex.getMessage());
	}

	@Test
	public void baseClientDetailsRoundTripsUnderJackson3() {
		BaseClientDetails details = jackson3.readValue(
				"{\"client_id\":\"foo\",\"scope\":\"read  write\",\"authorized_grant_types\":[\"authorization_code\"],"
						+ "\"resource_ids\":\"api\",\"unknown_field\":\"ignored\"}",
				BaseClientDetails.class);
		assertEquals("foo", details.getClientId());
		assertEquals(OAuth2Utils.parseParameterList("read write"), details.getScope());
		assertEquals(OAuth2Utils.parseParameterList("authorization_code"), details.getAuthorizedGrantTypes());
		assertEquals(OAuth2Utils.parseParameterList("api"), details.getResourceIds());
	}

	@Test
	public void approvalDatesUseIsoFormatUnderJackson3() {
		Approval approval = new Approval("user", "client", "read", new Date(1234567890123L),
				ApprovalStatus.APPROVED, new Date(1234567890123L));

		String json3 = jackson3.writeValueAsString(approval);

		assertTrue("expected ISO date in " + json3, json3.contains("\"2009-02-1"));
		Approval read = jackson3.readValue(json3, Approval.class);
		assertEquals(approval.getExpiresAt(), read.getExpiresAt());
		assertEquals(approval.getUserId(), read.getUserId());
	}
}
