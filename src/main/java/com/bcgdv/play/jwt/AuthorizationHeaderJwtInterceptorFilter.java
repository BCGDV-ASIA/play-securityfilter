/*
 * SecurityHeaderInterceptorFilter
 */
package com.bcgdv.play.jwt;

import akka.stream.Materializer;
import com.bcgdv.play.jwt.validation.HttpRequestValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Filter;
import play.mvc.Http;
import play.mvc.Result;

import javax.inject.Inject;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;

import static com.bcgdv.play.jwt.util.JSONResponseHelper.forbiddenAsJSON;

/**
 * Main entry point for play framework. Define this filter inside your application to intercept
 * incoming HTTP requests and extract a JWT token from the HTTP Authorization Header. The token is
 * passed to httpRequestValidator for validation, while requests without a valid token or header are rejected.
 */
public class AuthorizationHeaderJwtInterceptorFilter extends Filter {


    /**
     * Logger
     */
    protected static final Logger logger = LoggerFactory.getLogger(AuthorizationHeaderJwtInterceptorFilter.class);


    /**
     * has a httpRequestValidator
     */
    protected HttpRequestValidator httpRequestValidator;


    /**
     * Log and error messages
     */
    protected static String SECURITY_SERVICE_TIME = "security service validated request {} in securityServiceValidationTimeMs={}";


    /**
     * Default constructor
     * @param mat the materializer needed by play
     * @param httpRequestValidator the request validator
     */
    @Inject
    public AuthorizationHeaderJwtInterceptorFilter(Materializer mat, HttpRequestValidator httpRequestValidator) {
        super(mat);
        this.httpRequestValidator = httpRequestValidator;
    }

    /**
     * Filter execution chain of command
     * @param nextFilter nextFilter is what you pass into when validation passes
     * @param requestHeader the request header inc. token
     * @return either delegates to controller or returns 403 forbidden canned response as JSON
     */
    @Override
    public CompletionStage<Result> apply(
            Function<Http.RequestHeader, CompletionStage<Result>> nextFilter,
            Http.RequestHeader requestHeader) {
        long before = System.currentTimeMillis();

        Optional<String> headerError = httpRequestValidator.validate(requestHeader);

        if (headerError.isPresent()) {
            logger.info(SECURITY_SERVICE_TIME, requestHeader.uri(), getElapsed(before));
            return CompletableFuture.completedFuture(forbiddenAsJSON());
        } else {
            logger.info(SECURITY_SERVICE_TIME, requestHeader.uri(), getElapsed(before));
            return nextFilter.apply(requestHeader).thenApply(result -> {
                return result;
            });
        }
    }

    /**
     * helper for calculating execution time
     * @param before in millis
     * @return execution tim in millis
     */
    protected long getElapsed(long before) {
        return System.currentTimeMillis() - before;
    }
}