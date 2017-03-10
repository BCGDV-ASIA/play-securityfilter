/*
 * AbstractVerifier
 */
package com.bcgdv.play.jwt.validation;

import com.bcgdv.jwt.models.Token;
import com.bcgdv.play.jwt.util.PublicKeyCache;
import com.bcgdv.play.services.Api;
import com.simonmittag.cryptoutils.asymmetric.KeyHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies a JWT token signature with the sender's public key.
 */
public abstract class JwtSignatureValidationService {
    protected static final String PUBKEY_CONTEXT_PATH = "/pubkey";
    protected static final String VALIDATED_TOKEN = "validated %s token integrity for {} from {} ";
    protected static final String NOT_VALIDATED_TOKEN = "unable to verify %s token, cause: ";
    protected static final String NOT_VALIDATED_CACHED_TOKEN = "unable to verify %s token, but since this key was cached we will try fetch a new one";

    protected static final Logger logger = LoggerFactory.getLogger(JwtSignatureValidationService.class);
    protected static final String DOTS = "...";

    protected PublicKeyCache publicKeyCache;
    protected Api api;


    /**
     * Initialize with api for remote callbacks and common public key cache
     *
     * @param api            the remote api
     * @param publicKeyCache the public key cache.
     */
    public JwtSignatureValidationService(Api api, PublicKeyCache publicKeyCache) {
        this.publicKeyCache = publicKeyCache;
        this.api = api;
    }


    /**
     * Fetch a public key and do so from remote service if it's not in local cache.
     *
     * @param context the token's context is the cache key
     * @return the key type.
     */
    protected String fetchCachedPublicKey(String context) {
        String serverPubkey = publicKeyCache.getKey(context);
        if (serverPubkey == null) {
            serverPubkey = fetchRemoteServerPublicKey(context);
            publicKeyCache.addKey(context, serverPubkey);
        }
        return serverPubkey;
    }


    /**
     * Visit remote service/pubkey url and fetch key object from JSON response
     *
     * @param serverUrl remote server URL
     * @return the pubkey as base64 encoded string
     */
    protected String fetchRemoteServerPublicKey(String serverUrl) {
        return api.get(serverUrl).findPath("key").asText();
    }


    /**
     * Build the key path
     *
     * @param context the context
     * @return the relative path
     */
    protected String buildKeyPath(String context) {
        return context + PUBKEY_CONTEXT_PATH;
    }


    /**
     * Override to implement token type
     *
     * @return see @TokenType
     */
    protected abstract String getTokenType();


    /**
     * Valides a JWT token by checking signature first with cached, then with remote public key
     *
     * @param token   the token
     * @param context the verification key
     * @throws JwtValidationException if signature cannot be validated
     */
    public void checkSignatureInContext(String token, String context) throws JwtValidationException {
        String serverPubkey = null;
        try {
            serverPubkey = fetchCachedPublicKey(buildKeyPath(context));
            JwtUtil.validateSignatureWithKey(token, KeyHelper.deserializePublicKey(serverPubkey));
        } catch (Exception e) {
            logger.debug(String.format(NOT_VALIDATED_CACHED_TOKEN, getTokenType()));
            serverPubkey = fetchRemoteServerPublicKey(buildKeyPath(context));
            try {
                JwtUtil.validateSignatureWithKey(token, KeyHelper.deserializePublicKey(serverPubkey));
            } catch (Exception e1) {
                logger.warn(String.format(NOT_VALIDATED_TOKEN, getTokenType()) + e.getMessage());
                throw new RuntimeException(e);
            }
        }
        logger.debug(String.format(VALIDATED_TOKEN, getTokenType()), scramble(token), context);
    }


    /**
     * Scramble token before logging or printing to console
     *
     * @param token the raw token
     * @return the obfuscated token
     */
    protected String scramble(String token) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(token.substring(0, 9));
            sb.append(DOTS);
            sb.append(token.substring(token.length() - 10));
            return sb.toString();
        } catch (Exception e) {
            return "{ token is scrambled }";
        }
    }


    /**
     * Override token type for client token
     */
    public static class ForClientToken extends JwtSignatureValidationService {
        protected static final Logger logger = LoggerFactory.getLogger(ForClientToken.class);

        public ForClientToken(Api api, PublicKeyCache publicKeyCache) {
            super(api, publicKeyCache);
        }

        @Override
        protected String getTokenType() {
            return Token.Type.CLIENT.toString();
        }

    }


    /**
     * Override token type for server token
     */
    public static class ForServerToken extends JwtSignatureValidationService {

        protected static final Logger logger = LoggerFactory.getLogger(ForServerToken.class);

        public ForServerToken(Api api, PublicKeyCache publicKeyCache) {
            super(api, publicKeyCache);
        }

        @Override
        protected String getTokenType() {
            return Token.Type.SERVER.toString();
        }
    }


    /**
     * Override token type for session token
     */
    public static class ForSessionToken extends JwtSignatureValidationService {
        protected static final Logger logger = LoggerFactory.getLogger(ForSessionToken.class);

        public ForSessionToken(Api api, PublicKeyCache publicKeyCache) {
            super(api, publicKeyCache);
        }

        @Override
        protected String getTokenType() {
            return Token.Type.SESSION.toString();
        }
    }
}
