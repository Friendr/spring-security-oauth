/*
 * Copyright 2011-2012 the original author or authors.
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
package org.springframework.security.oauth2.http.converter.jaxb;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.util.Date;

import jakarta.xml.bind.JAXBContext;

import org.junit.Before;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.util.ReflectionUtils;

/**
 * Base class for the JAXB message converter tests.
 *
 * <p>
 * Previously this class froze the clock with PowerMock's {@code mockStatic(System.class)}; PowerMock cannot
 * run on modern JVMs, so instead the mocked expiration {@link Date} answers
 * {@code System.currentTimeMillis() + 10500} at call time, which serializes as {@code expires_in} 10 (the
 * 500ms slack absorbs the time between the converter's clock read and the expiration read). Deserialization
 * assertions must use a small tolerance instead of exact expiration equality.
 * </p>
 *
 * @author Rob Winch
 */
abstract class BaseJaxbMessageConverterTest {
	protected static final String OAUTH_ACCESSTOKEN_NOEXPIRES = "<oauth><access_token>SlAV32hkKG</access_token></oauth>";
	protected static final String OAUTH_ACCESSTOKEN_NOREFRESH = "<oauth><access_token>SlAV32hkKG</access_token><expires_in>10</expires_in></oauth>";
	protected static final String OAUTH_ACCESSTOKEN = "<oauth><access_token>SlAV32hkKG</access_token><expires_in>10</expires_in><refresh_token>8xLOxBtZp8</refresh_token></oauth>";

	/**
	 * Maximum drift allowed when comparing an expected expiration (clock + 10500ms) with an expiration
	 * reconstructed from {@code expires_in}.
	 */
	protected static final long EXPIRATION_TOLERANCE_MILLIS = 2000;

	protected MediaType contentType;
	protected ByteArrayOutputStream output;

	protected Date expiration;
	protected HttpOutputMessage outputMessage;
	protected HttpInputMessage inputMessage;
	protected HttpHeaders headers;
	protected JAXBContext context;

	@Before
	public final void setUp() throws Exception {
		expiration = mock(Date.class);
		outputMessage = mock(HttpOutputMessage.class);
		inputMessage = mock(HttpInputMessage.class);
		headers = mock(HttpHeaders.class);
		context = mock(JAXBContext.class);

		when(expiration.before(any(Date.class))).thenReturn(false);
		when(expiration.getTime()).thenAnswer(invocation -> System.currentTimeMillis() + 10500L);

		output = new ByteArrayOutputStream();
		contentType = MediaType.APPLICATION_XML;
		when(headers.getContentType()).thenReturn(contentType);
		when(outputMessage.getHeaders()).thenReturn(headers);
		when(outputMessage.getBody()).thenReturn(output);
	}


	protected InputStream createInputStream(String in) throws UnsupportedEncodingException {
		return new ByteArrayInputStream(in.getBytes("UTF-8"));
	}

	protected String getOutput() throws UnsupportedEncodingException {
		return output.toString("UTF-8");
	}

	protected void useMockJAXBContext(Object object, Class<?> jaxbClassToBeBound) throws Exception {
		JAXBContext jaxbContext = JAXBContext.newInstance(jaxbClassToBeBound);
		when(context.createMarshaller()).thenReturn(jaxbContext.createMarshaller());
		when(context.createUnmarshaller()).thenReturn(jaxbContext.createUnmarshaller());
		Field field = ReflectionUtils.findField(object.getClass(), null, JAXBContext.class);
		ReflectionUtils.makeAccessible(field);
		ReflectionUtils.setField(field, object, context);
	}
}
