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
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/**
 * Action is a decorator for the action method call that is run for all @Token annotated methods.
 */
public class JwtValidationPlayAction extends Action<Secure> {

    /**
     * Has an assertionValidator to delegate to.
     */
    protected AssertionValidator assertionValidator;


    /**
     * Build with Assertionvalidator
     * @param assertionValidator the assertion validator
     */
    public JwtValidationPlayAction(AssertionValidator assertionValidator) {
        this.assertionValidator=assertionValidator;
    }

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
     * Validation of token as controller action. Use to perform, i.e. authorization
     *
     * @param context the http context needed for execution
     * @return a result wrapped in CompletionStage
     */
    @Override
    public CompletionStage<Result> call(Http.Context context) {
        logger.debug(EXECUTING_ACTION, Arrays.toString(configuration.type()), uri(context));
        try {
            if(!assertionValidator.validate(
                    configuration.type(),
                    requestTokenType(context),
                    requestAssertions(context),
                    context.request())) {
                return forbiddenAsFuture();
            }
        } catch (JwtValidationException e) {
            logger.warn("JWT Validation Exception, cause: " + e.getMessage());
            try {
                return forbiddenAsFuture();
            } catch (Exception e1) {
                throw new RuntimeException("unable to process request, cause: " + e.getMessage());
            }
        } catch (Exception e) {
            logger.error("i got an error while decrypting an already validated token, this should never happen" + e.getMessage());
            return forbiddenAsFuture();

        }
        return delegate.call(context);
    }

    /**
     * Canned forbidden response as Completeable Future
     * @return the 403 as JSON, wrapped in future.
     */
    protected CompletableFuture<Result> forbiddenAsFuture() {
        return CompletableFuture.completedFuture(JSONResponseHelper.forbiddenAsJSON());
    }

    /**
     * Get JWT assertions from request
     * @param context http context
     * @return extracted assertions
     */
    protected Map requestAssertions(Http.Context context) {
        return jwtPayloadValidationService.extractAssertions(headers(context));
    }

    /**
     * Get token type from request
     * @param context the http context
     * @return the token type
     */
    protected Token.Type requestTokenType(Http.Context context) {
        return jwtPayloadValidationService.extractTokenType(headers(context));
    }

    /**
     * Get uri from request
     * @param context the http context
     * @return the uri as String
     */
    protected String uri(Http.Context context) {
        return context.request().uri();
    }

    /**
     * Get headers from request
     * @param context the http context
     * @return the headers as Map
     */
    protected Map<String, String[]> headers(Http.Context context) {
        return context.request().headers();
    }
}