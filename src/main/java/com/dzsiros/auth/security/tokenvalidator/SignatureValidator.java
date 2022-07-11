package com.dzsiros.auth.security.tokenvalidator;

import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_TOKEN;

import java.security.interfaces.RSAPublicKey;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class SignatureValidator implements OAuth2TokenValidator<Jwt> {
    private final String issuer;

    public SignatureValidator(String issuer) {
        this.issuer = issuer;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        DecodedJWT jwt = JWT.decode(token.getTokenValue());
        JwkProvider provider = new GuavaCachedJwkProvider(new UrlJwkProvider(issuer));
        try {
            Jwk jwk = provider.get(jwt.getKeyId());
            // private key only required for signing, but we only use verifying which can be done by using public key only
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            algorithm.verify(jwt);
        } catch (JwkException e) {
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error(INVALID_TOKEN, e.getMessage(), null)
            );
        }

        return OAuth2TokenValidatorResult.success();
    }
}
