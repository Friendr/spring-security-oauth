package org.springframework.security.oauth2.provider.endpoint;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

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
        return jwkSet.toJSONObject();
    }

}
