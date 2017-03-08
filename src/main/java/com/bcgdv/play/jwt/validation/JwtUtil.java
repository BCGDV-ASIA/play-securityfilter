package com.bcgdv.play.jwt.validation;

import com.bcgdv.jwt.models.Token;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Preconditions;
import com.google.common.net.HttpHeaders;
import com.simonmittag.cryptoutils.SimpleCipher;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.libs.Json;
import play.mvc.Http;

import java.security.Key;
import java.util.Base64;
import java.util.Map;

/**
 * Helper methods for JWT token validation
 */
public final class JwtUtil {
    public static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    /**
     * Default, don't use
     */
    protected JwtUtil() {
        //use static helper methods instead
    }


    /**
     * Find creation time of encoded JWT Token
     *
     * @param encodedToken
     * @return
     */
    public static Long getDateCreated(String encodedToken) {
        return getDateCreated(
                Json.parse(
                        extractJwtPayload(encodedToken)));

    }


    /**
     * Find created time in JsonNode object
     *
     * @param jsonNode
     * @return
     */
    public static Long getDateCreated(JsonNode jsonNode) {
        return jsonNode.findPath(Token.Fields.dateCreated.toString()).asLong();
    }


    /**
     * When was the Authorization Header created?
     *
     * @param requestHeader
     * @return
     */
    public static Long getDateCreated(Http.RequestHeader requestHeader) {
        return getDateCreated(
                getAuthorizationHeaderContents(
                        requestHeader.headers()));
    }


    /**
     * Extract the Authorization header from headers array
     *
     * @param headers
     * @return
     */
    public static String getAuthorizationHeaderContents(Map<String, String[]> headers) {
        try {
            return headers.get(HttpHeaders.AUTHORIZATION)[0];
        } catch (Exception e) {
            return "";
        }
    }


    /**
     * Extract the JWT token payload as String
     *
     * @param token the token
     * @return the payload
     */
    public static String extractJwtPayload(String token) {
        Preconditions.checkArgument(
                token.split("\\.").length == 3,
                "Invalid Jwt token , Jwt token should have header,claims and signature");
        String payload = token.split("\\.")[1];
        return new String(Base64.getDecoder().decode(payload));
    }


    /**
     * Verify the JWT signature
     *
     * @param token the token
     * @param key   the key
     * @throws JwtValidationException if something goes wrong.
     */
    public static void validateSignatureWithKey(String token, Key key) throws JwtValidationException {
        try {
            Jwts.parser().setSigningKey(key).parse(token);
        } catch (Exception e) {
            logger.warn("Cannot verify the signature, I will reject this request, cause: ", e.getMessage());
            throw new JwtValidationException(e);
        }
    }


    /**
     * Decrypts the token's secret and attempts to parse it as a JSON node.
     *
     * @param simpleCipher passed in cipher. Note this is the same as the cipher used to create the token.
     * @param jsonNode
     * @return decrypted secret as JSON node.
     * @throws JwtValidationException
     */
    public static JsonNode extractAndDecryptSecret(SimpleCipher simpleCipher, JsonNode jsonNode) throws JwtValidationException {
        try {
            String secret = jsonNode.findPath(Token.Fields.secret.toString()).asText();
            Preconditions.checkArgument(
                    !StringUtils.isBlank(secret),
                    "Secret should be present in payload");
            String decryptedPayload = simpleCipher.decrypt(secret);
            return Json.parse(decryptedPayload);
        } catch (Exception e) {
            logger.warn("Cannot decrypt given secret, cause: ", e.getMessage());
            throw new JwtValidationException(e);
        }
    }

}
