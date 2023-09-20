package org.springframework.security.oauth2.provider.endpoint;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.security.oauth2.provider.jwks.NbfExpJwkPredicate;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;
import java.util.Map;

@FrameworkEndpoint
public class JwksEndpoint {

    private final JWKSet jwkSet;

    public JwksEndpoint(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @RequestMapping(path = "/.well-known/jwks.json", method = RequestMethod.GET, produces = "application/json;charset=UTF-8")
    @ResponseBody
    public Map<String, Object> jwks() {
        return filteredJwkSet().toJSONObject();
    }

    /**
     * Returns filered {@link JWKSet} that doesn't contain {@link JWK}s that are not valid yet or expired already
     * (i.e. the condition <code>jwk.nbf <= currentTimestamp < jwk.exp</code> is <code>false</code>).
     *
     * @return filtered {@code JWKSet}
     */
    private JWKSet filteredJwkSet() {
        List<JWK> filteredJwkList = jwkSet.getKeys().stream()
                .filter(new NbfExpJwkPredicate())
                .toList();
        return new JWKSet(filteredJwkList);
    }

}
