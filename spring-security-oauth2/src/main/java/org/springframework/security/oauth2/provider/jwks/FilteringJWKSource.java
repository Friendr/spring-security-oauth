package org.springframework.security.oauth2.provider.jwks;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.util.List;
import java.util.function.Predicate;

public class FilteringJWKSource<C extends SecurityContext> implements JWKSource<C> {

    private final JWKSource<C> delegate;
    private final Predicate<JWK> predicate;

    public FilteringJWKSource(JWKSource<C> delegate, Predicate<JWK> predicate) {
        this.delegate = delegate;
        this.predicate = predicate;
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
        List<JWK> jwks = delegate.get(jwkSelector, context);
        return jwks.stream().filter(predicate).toList();
    }

}
