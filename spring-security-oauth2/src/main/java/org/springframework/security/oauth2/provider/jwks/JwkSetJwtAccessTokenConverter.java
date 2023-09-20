package org.springframework.security.oauth2.provider.jwks;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.security.KeyPair;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwkSetJwtAccessTokenConverter extends JwtAccessTokenConverter {

    private final JWKSet jwkSet;
    private final NimbusJwtEncoder encoder;
    private final NimbusJwtDecoder decoder;

    public JwkSetJwtAccessTokenConverter(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
        this.encoder = createEncoder(jwkSet);
        this.decoder = createDecoder(jwkSet);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
    }

    private NimbusJwtEncoder createEncoder(JWKSet jwkSet) {
        JWKSource<SecurityContext> jwkSource = new LastKeyJWKSource<>(
                new FilteringJWKSource<>(
                        new ImmutableJWKSet<>(jwkSet), new NbfExpJwkPredicate()
                )
        );
        return new NimbusJwtEncoder(jwkSource);
    }

    private NimbusJwtDecoder createDecoder(JWKSet jwkSet) {
        JWKSource<SecurityContext> jwkSource = new FilteringJWKSource<>(
                new ImmutableJWKSet<>(jwkSet), new NbfExpJwkPredicate()
        );

        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsVerificationKeySelector(jwkSet, jwkSource));

        return new NimbusJwtDecoder(jwtProcessor);
    }

    private JWSKeySelector<SecurityContext> jwsVerificationKeySelector(JWKSet jwkSet,
            JWKSource<SecurityContext> jwkSource) {

        Set<JWSAlgorithm> jwsAlgorithms = jwkSet.getKeys().stream()
                .map(JWK::getAlgorithm)
                .map(alg -> alg != null ? JWSAlgorithm.parse(alg.getName()) : JWSAlgorithm.RS256)
                .collect(Collectors.toUnmodifiableSet());

        return new JWSVerificationKeySelector<>(jwsAlgorithms, jwkSource);
    }

    @Override
    public void setVerifier(SignatureVerifier verifier) {
        throw new UnsupportedOperationException("Verifier is not used by " + JwkSetJwtAccessTokenConverter.class);
    }

    @Override
    public void setSigner(Signer signer) {
        throw new UnsupportedOperationException("Signer is not used by " + JwkSetJwtAccessTokenConverter.class);
    }

    @Override
    public void setKeyPair(KeyPair keyPair) {
        throw new UnsupportedOperationException("KeyPair is not used by " + JwkSetJwtAccessTokenConverter.class);
    }

    @Override
    public void setSigningKey(String key) {
        throw new UnsupportedOperationException("SigningKey is not used by " + JwkSetJwtAccessTokenConverter.class);
    }

    @Override
    public void setVerifierKey(String key) {
        throw new UnsupportedOperationException("VerifierKey is not used by " + JwkSetJwtAccessTokenConverter.class);
    }

    /**
     * Always returns empty map. Should not be used.
     *
     * @return an empty map
     */
    @Override
    public Map<String, String> getKey() {
        return Map.of();
    }

    @Override
    public boolean isPublic() {
        return true;
    }

    @Override
    protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        JwsHeader jwsHeader = JwsHeader
                .with(SignatureAlgorithm.RS256)
                .type(JOSEObjectType.JWT.getType())
                .build();

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .claims(claims -> claims.putAll(convertAccessToken(accessToken, authentication)))
                .build();

        Jwt jwt = encoder.encode(JwtEncoderParameters.from(jwsHeader, claimsSet));

        return jwt.getTokenValue();
    }

    @Override
    protected Map<String, Object> decode(String token) {
        try {
            Jwt jwt = decoder.decode(token);
            Map<String, Object> claims = jwt.getClaims();
            getJwtClaimsSetVerifier().verify(claims);

            return claims;
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid or expired token", e);
        }
    }

    public JWKSet getJwkSet() {
        return jwkSet;
    }

}
