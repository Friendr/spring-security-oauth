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
package org.springframework.security.oauth2.provider.expression;

import java.util.function.Supplier;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * <p>
 * A security expression handler that can handle default web security expressions plus the set provided by
 * {@link OAuth2SecurityExpressionMethods} using the variable oauth2 to access the methods. For example, the expression
 * <code>#oauth2.clientHasRole('ROLE_ADMIN')</code> would invoke {@link OAuth2SecurityExpressionMethods#clientHasRole}.
 * </p>
 * <p>
 * By default the {@link OAuth2ExpressionParser} is used. If this is undesirable one can inject their own
 * {@link ExpressionParser} using {@link #setExpressionParser(ExpressionParser)}.
 * </p>
 * <p>
 * Since Spring Security 7 removed the {@code FilterInvocation}-based
 * {@code DefaultWebSecurityExpressionHandler}, this handler is now a
 * {@link DefaultHttpSecurityExpressionHandler} operating on {@link RequestAuthorizationContext} and is meant to be
 * used with {@link WebExpressionAuthorizationManager}
 * (e.g. {@code WebExpressionAuthorizationManager.withExpressionHandler(handler).expression("#oauth2.hasScope('read')")}).
 * </p>
 *
 * @author Dave Syer
 * @author Rob Winch
 *
 * @see OAuth2ExpressionParser
 */
public class OAuth2WebSecurityExpressionHandler extends DefaultHttpSecurityExpressionHandler {
	public OAuth2WebSecurityExpressionHandler() {
		setExpressionParser(new OAuth2ExpressionParser(getExpressionParser()));
	}

	@Override
	protected StandardEvaluationContext createEvaluationContextInternal(Authentication authentication,
			RequestAuthorizationContext context) {
		StandardEvaluationContext ec = super.createEvaluationContextInternal(authentication, context);
		ec.setVariable("oauth2", new OAuth2SecurityExpressionMethods(authentication));
		return ec;
	}

	@Override
	public EvaluationContext createEvaluationContext(Supplier<? extends Authentication> authentication,
			RequestAuthorizationContext context) {
		EvaluationContext ec = super.createEvaluationContext(authentication, context);
		if (ec instanceof StandardEvaluationContext standardEvaluationContext) {
			standardEvaluationContext.setVariable("oauth2", new OAuth2SecurityExpressionMethods(authentication.get()));
		}
		return ec;
	}
}
