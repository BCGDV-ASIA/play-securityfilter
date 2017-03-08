package com.bcgdv.play.jwt.validation;

import com.bcgdv.jwt.models.Token;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.inject.Singleton;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.libs.Json;
import play.mvc.Http;

/**
 * Validates JWT Token integrity, not specific to TokenType
 */
@Singleton
public class JwtIntegrityValidationService {
    //Jwt comprises of header,claims and signature separated by '.'

    private static final Logger logger = LoggerFactory.getLogger(JwtIntegrityValidationService.class);

    /**
     * Checks for integrity of JWT Token
     *
     * @param requestHeader
     * @throws JwtValidationException
     */
    public void requestHasWellFormedToken(Http.RequestHeader requestHeader) throws JwtValidationException {
        hasAuthHeader(requestHeader)
                .andHasJWTToken(requestHeader)
                .thatIsNotExpired(requestHeader);
    }

    /**
     * Does the http  request have an Authorization header?
     *
     * @param requestHeader
     * @return service for builder pattern
     * @throws JwtValidationException
     */
    protected JwtIntegrityValidationService hasAuthHeader(Http.RequestHeader requestHeader) throws JwtValidationException {
        logger.debug("Validating Authorization Header for given request {}", requestHeader.uri());
        if (JwtUtil.getAuthorizationHeaderContents(requestHeader.headers()).isEmpty()) {
            throw new JwtValidationException();
        }
        return this;
    }

    /**
     * Does the http request have a valid JWT token?
     *
     * @param requestHeader
     * @return service for builder pattern
     * @throws JwtValidationException
     */
    protected JwtIntegrityValidationService andHasJWTToken(Http.RequestHeader requestHeader) throws JwtValidationException {
        logger.debug("Validating jwt length for given request {}", requestHeader.uri());
        String jwt = JwtUtil.getAuthorizationHeaderContents(requestHeader.headers());
        if (jwt.split("\\.").length != Token.LENGTH) {
            throw new JwtValidationException();
        }
        return this;
    }

    /**
     * Does the http request JWT token have an unexpired token?
     *
     * @param requestHeader
     * @throws JwtValidationException
     */
    protected void thatIsNotExpired(Http.RequestHeader requestHeader) throws JwtValidationException {
        String payload = JwtUtil.extractJwtPayload(JwtUtil.
                getAuthorizationHeaderContents(requestHeader.headers()));
        JsonNode jsonNode = Json.parse(payload);
        Long expiryTimeInMilliSeconds =
                jsonNode.findPath(Token.Fields.expiryInMilliSeconds.toString()).asLong();
        Long createdTime = JwtUtil.getDateCreated(jsonNode);
        if (isExpired(createdTime, expiryTimeInMilliSeconds)) {
            throw new JwtValidationException();
        }
    }

    /**
     * Calculate if the token is expired?
     *
     * @param createdTime
     * @param expiryTimeInMilliSeconds
     * @return true | false
     */
    public static boolean isExpired(Long createdTime, Long expiryTimeInMilliSeconds) {
        if (expiryTimeInMilliSeconds == Token.EXPIRY_NEVER ||
                hasNegative(expiryTimeInMilliSeconds)) {
            return false;
        } else {
            Long now = new DateTime().getMillis();
            if (createdTime > now) {
                return false;
            }
            Long duration = now - createdTime;
            return (duration > expiryTimeInMilliSeconds);
        }
    }

    /**
     * Is the Token meant to never expire?
     *
     * @param expiryTimeInMilliSeconds
     * @return true | false
     */
    protected static boolean hasNegative(Long expiryTimeInMilliSeconds) {
        return Math.abs(expiryTimeInMilliSeconds) != expiryTimeInMilliSeconds;
    }
}
