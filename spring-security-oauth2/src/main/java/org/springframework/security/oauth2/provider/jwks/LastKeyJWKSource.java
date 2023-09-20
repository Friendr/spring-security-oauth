package org.springframework.security.oauth2.provider.jwks;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.util.List;

/**
 * An implementation of {@link JWKSource} that wraps other {@code JWKSource}, but returns the list of JWKs, containing
 * only the last {@code JWK} of the list, returned by a wrapped {@code JWKSource}.
 * @param <C>
 */
public class LastKeyJWKSource<C extends SecurityContext> implements JWKSource<C> {

    private final JWKSource<C> delegate;

    public LastKeyJWKSource(JWKSource<C> delegate) {
        this.delegate = delegate;
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
        List<JWK> jwks = delegate.get(jwkSelector, context);
        if (jwks.size() < 2) {
            return jwks;
        }
        return List.of(jwks.get(jwks.size() - 1));
    }

}
