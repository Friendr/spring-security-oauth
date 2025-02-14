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
package demo;

import static org.junit.Assert.assertTrue;

import org.springframework.boot.test.context.SpringBootTest;
import sparklr.common.AbstractAuthorizationCodeProviderTests;

/**
 * @author Dave Syer
 */
@SpringBootTest(classes = Application.class)
public class AuthorizationCodeProviderTests extends AbstractAuthorizationCodeProviderTests {

	protected void verifyAuthorizationPage(String page) {
		assertTrue(page.contains("action=\"/oauth/authorize\""));
		assertTrue(page.contains("<input name=\"user_oauth_approval\""));
		assertTrue(page.contains("type=\"radio")); // approval store
	}

}
