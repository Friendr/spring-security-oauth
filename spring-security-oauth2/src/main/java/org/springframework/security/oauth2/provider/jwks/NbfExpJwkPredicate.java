package org.springframework.security.oauth2.provider.jwks;

import com.nimbusds.jose.jwk.JWK;

import java.time.Instant;
import java.util.Date;
import java.util.function.Predicate;

public class NbfExpJwkPredicate implements Predicate<JWK> {

    @Override
    public boolean test(JWK jwk) {
        Instant currentTime = Instant.now();
        Instant nbf = toInstant(jwk.getNotBeforeTime(), Instant.MIN);
        Instant exp = toInstant(jwk.getExpirationTime(), Instant.MAX);

        return !currentTime.isBefore(nbf) && currentTime.isBefore(exp);
    }

    private Instant toInstant(Date date, Instant defaultIfNull) {
        if (date == null) {
            return defaultIfNull;
        }
        return date.toInstant();
    }

}
