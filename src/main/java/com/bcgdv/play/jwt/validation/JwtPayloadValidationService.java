package com.bcgdv.play.jwt.validation;

import com.bcgdv.jwt.models.Token;
import com.bcgdv.play.jwt.model.AnnotationInfo;
import com.bcgdv.play.jwt.util.JwtAnnotationHelper;
import com.bcgdv.play.jwt.util.PublicKeyCache;
import com.bcgdv.play.services.Api;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Preconditions;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.inject.name.Named;
import com.simonmittag.cryptoutils.SimpleCipher;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.libs.Json;
import play.mvc.Http;
import play.routing.Router;

import java.util.Map;
import java.util.Optional;

/**
 * Extract JWT Token payload for verification
 */
@Singleton
public class JwtPayloadValidationService {
    protected static final Logger logger = LoggerFactory.getLogger(JwtPayloadValidationService.class);

    protected Api api;
    protected SimpleCipher simpleCipher;
    protected PublicKeyCache publicKeyCache;

    /**
     * Needs Api for callbacks, SimpleCipher for crypto operation and publicKeyCache for managing keys.
     *
     * @param api            The Microservice Api
     * @param simpleCipher   The cipher used for JWT operation
     * @param publicKeyCache key cache
     */
    @Inject
    public JwtPayloadValidationService(Api api,
                                       @Named("symmetricCipher") SimpleCipher simpleCipher,
                                       PublicKeyCache publicKeyCache) {
        this.api = api;
        this.simpleCipher = simpleCipher;
        this.publicKeyCache = publicKeyCache;
    }

    /**
     * Validate tokens match the current method's annotations
     *
     * @param tokentype the token type
     * @param requestHeader all http request headers
     * @param annotationInfo the annotation info
     * @throws JwtValidationException if token type for annotation not valid, i.e. @Secure(NOT_VALID)
     */
    public void validateTokenType(String tokentype,
                                  Http.RequestHeader requestHeader,
                                  AnnotationInfo annotationInfo) throws JwtValidationException {
        String className = Preconditions.checkNotNull(requestHeader.tags().get(Router.Tags.ROUTE_CONTROLLER));
        String methodName = Preconditions.checkNotNull(requestHeader.tags().get(Router.Tags.ROUTE_ACTION_METHOD));
        Optional<Token.Type[]> tokens =
                JwtAnnotationHelper.findTokenTypesForSecureAnnotation(
                        annotationInfo.getSecure(), className, methodName);

        if (tokens.isPresent()) {
            for (Token.Type t : tokens.get()) {
                if (t != Token.Type.NONE && t.name().equalsIgnoreCase(tokentype)) {
                    return;
                }
            }
        }
        logger.warn("For given request {} allowed tokens in method are {} but got {}", requestHeader.uri(), ArrayUtils.toString(tokens.get()), tokentype);
        throw new JwtValidationException();
    }

    /**
     * Extract tokenType for token by decrypting the secret and finding the tokenType JSON node in the payload
     *
     * @param headers headers from HTTP request
     * @return the token type as String
     * @throws JwtValidationException if token type cannot be established
     */
    public String extractTokenType(Map<String, String[]> headers) throws JwtValidationException {
        String token =
                JwtUtil.getAuthorizationHeaderContents(headers);
        JsonNode payloadNode =
                JwtUtil.extractAndDecryptSecret(
                        simpleCipher, Json.parse(
                                JwtUtil.extractJwtPayload(token)));

        return payloadNode.findPath(Token.Fields.tokenType.toString()).asText();
    }

    /**
     * Extract tokentype and payloadsignature, validate both
     *
     * @param requestHeader  the request header
     * @param annotationInfo the annotation info
     * @throws JwtValidationException if payload cannot be validated
     */
    public void validateJwtPayload(Http.RequestHeader requestHeader,
                                   AnnotationInfo annotationInfo) throws JwtValidationException {
        String token = JwtUtil.getAuthorizationHeaderContents(requestHeader.headers());
        JsonNode payloadNode = JwtUtil.extractAndDecryptSecret(
                simpleCipher,
                Json.parse(JwtUtil.extractJwtPayload(token)));
        String tokenType = payloadNode.findPath(Token.Fields.tokenType.toString()).asText();
        if (StringUtils.isBlank(tokenType)) {
            throw new JwtValidationException("token type not specified");
        }
        validateTokenType(tokenType, requestHeader, annotationInfo);
        validatePayloadSignature(tokenType, token, payloadNode);
    }

    /**
     * Validate payload signature by delegating to token specific validation subtype
     *
     * @param type        the type
     * @param token       the token
     * @param payloadNode the decrypted payload
     * @throws JwtValidationException if content validation fails for any reason
     */
    public void validatePayloadSignature(String type,
                                         String token,
                                         JsonNode payloadNode) throws JwtValidationException {
        String context = extractContext(payloadNode);
        switch (Token.Type.valueOf(type)) {
            case CLIENT:
                new JwtSignatureValidationService
                        .ForClientToken(api, publicKeyCache)
                        .checkSignatureInContext(token, context);
                break;
            case SESSION:
                new JwtSignatureValidationService
                        .ForSessionToken(api, publicKeyCache)
                        .checkSignatureInContext(token, context);
                break;
            case SERVER:
                new JwtSignatureValidationService
                        .ForServerToken(api, publicKeyCache)
                        .checkSignatureInContext(token, context);
                break;
            default:
                throw new JwtValidationException();
        }
    }

    /**
     * Extract context path from decrypted JSON payload
     *
     * @param payloadNode the tokens decrypted JSON payload
     * @return context as String
     * @throws JwtValidationException if the payload does not contain context.
     */
    protected String extractContext(JsonNode payloadNode) throws JwtValidationException {
        String senderContextPath = payloadNode.findPath(Token.Fields.context.toString()).asText(null);
        if (senderContextPath == null) {
            String message = "Verification context for server token cannot be null";
            logger.warn(message);
            throw new JwtValidationException(message);
        }
        return senderContextPath;
    }
}
