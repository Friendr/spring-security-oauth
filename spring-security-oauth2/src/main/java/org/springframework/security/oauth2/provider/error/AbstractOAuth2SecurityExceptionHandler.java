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
package org.springframework.security.oauth2.provider.error;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

/**
 * Convenient base class containing utility methods and dependency setters for security error handling concerns specific
 * to OAuth2 resources.
 *
 * @author Dave Syer
 * 
 */
public abstract class AbstractOAuth2SecurityExceptionHandler {

	/** Logger available to subclasses */
	protected final Log logger = LogFactory.getLog(getClass());

	private WebResponseExceptionTranslator<?> exceptionTranslator = new DefaultWebResponseExceptionTranslator();

	private OAuth2ExceptionRenderer exceptionRenderer = new DefaultOAuth2ExceptionRenderer();

	// This is from Spring MVC.
	private HandlerExceptionResolver handlerExceptionResolver = new DefaultHandlerExceptionResolver();

	public void setExceptionTranslator(WebResponseExceptionTranslator<?> exceptionTranslator) {
		this.exceptionTranslator = exceptionTranslator;
	}

	public void setExceptionRenderer(OAuth2ExceptionRenderer exceptionRenderer) {
		this.exceptionRenderer = exceptionRenderer;
	}

	protected final void doHandle(HttpServletRequest request, HttpServletResponse response, Exception authException)
			throws IOException, ServletException {
		try {
			ResponseEntity<?> result = exceptionTranslator.translate(authException);
			result = enhanceResponse(result, authException);
			exceptionRenderer.handleHttpEntityResponse(result, new ServletWebRequest(request, response));
			response.flushBuffer();
		}
		catch (ServletException e) {
			// Re-use some of the default Spring dispatcher behaviour - the exception came from the filter chain and
			// not from an MVC handler so it won't be caught by the dispatcher (even if there is one)
			if (handlerExceptionResolver.resolveException(request, response, this, e) == null) {
				throw e;
			}
		}
		catch (IOException e) {
			throw e;
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			// Wrap other Exceptions. These are not expected to happen
			throw new RuntimeException(e);
		}
	}

	/**
	 * Allow subclasses to manipulate the response before it is rendered.
	 * 
	 * Note : Only the {@link ResponseEntity} should be enhanced. If the
         * response body is to be customized, it should be done at the
         * {@link WebResponseExceptionTranslator} level.
	 * 
	 * @param result the response that was generated by the
	 * {@link #setExceptionTranslator(WebResponseExceptionTranslator) exception translator}.
	 * @param authException the authentication exception that is being handled
	 */
	protected ResponseEntity<?> enhanceResponse(ResponseEntity<?> result,
			Exception authException) {
		return result;
	}

}
