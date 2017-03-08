package com.bcgdv.play.jwt.validation;

import com.bcgdv.jwt.models.Token;
import com.bcgdv.play.jwt.Secure;
import com.bcgdv.play.jwt.util.JSONResponseHelper;
import com.google.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Result;

import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/**
 * Action is a decorator for the action method call that is run for all @Token annotated methods.
 */
public class JwtValidationPlayAction extends Action<Secure> {


    /**
     * Logger
     */
    protected static final Logger logger = LoggerFactory.getLogger(JwtValidationPlayAction.class);


    /**
     * Log/error messages
     */
    protected static final String EXECUTING_ACTION = "Executing customerId verification for token {} ,request {}";


    /**
     * Has a jwtPayloadValidationService
     */
    protected JwtPayloadValidationService jwtPayloadValidationService;


    /**
     * Build with Guice
     *
     * @param jwtPayloadValidationService the payload validation service
     */
    @Inject
    public JwtValidationPlayAction(JwtPayloadValidationService jwtPayloadValidationService) {
        this.jwtPayloadValidationService = jwtPayloadValidationService;
    }


    /**
     * This executes the action method after validating the customerID from the Token was in the request
     * path, queryString or body. Uses heuristics to determine what's a customerID.
     *
     * @param context the http context needed for execution
     * @return a result wrapped in CompletionStage
     */
    @Override
    public CompletionStage<Result> call(Http.Context context) {
        logger.debug(EXECUTING_ACTION, Arrays.toString(configuration.value()), context.request().uri());
        Token.Type[] annotatedTokens = configuration.value();

        try {
            String tokenType = extractTokenType(context);

            //
        } catch (JwtValidationException e) {
            logger.warn("JWT Validation Exception, cause: " + e.getMessage());
            try {
                return CompletableFuture.completedFuture(JSONResponseHelper.forbiddenAsJSON());
            } catch (Exception e1) {
                throw new RuntimeException("unable to process request, cause: " + e.getMessage());
            }
        } catch (Exception e) {
            logger.error("i got an error while decrypting an already validated token, this should never happen" + e.getMessage());
            return CompletableFuture.completedFuture(JSONResponseHelper.forbiddenAsJSON());

        }
        return delegate.call(context);
    }


    /**
     * Get token type
     *
     * @param context the http context with request / headers
     * @return the token type of the embedded token.
     * @throws JwtValidationException if something goes wrong during extraction
     */
    protected String extractTokenType(Http.Context context) throws JwtValidationException {
        return jwtPayloadValidationService.extractTokenType(context.request().headers());
    }
}