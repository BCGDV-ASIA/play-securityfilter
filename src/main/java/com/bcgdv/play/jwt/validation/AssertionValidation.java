/**
 * AssertionValidation
 */
package com.bcgdv.play.jwt.validation;

import com.bcgdv.jwt.models.Token;
import play.mvc.Http;

import java.util.Map;

/**
 * Check assertions
 */
public interface AssertionValidation {

    /**
     * Validate assertions for
     * @param annotatedTokens these annotated tokens
     * @param requestTokenType the passed in token type from the http request
     * @param requestAssertions the assertions made by the passed in token
     * @param request the actual request if needed, i.e. headers or body
     * @return return true for pass and false for fail
     */
    boolean with(Token.Type[] annotatedTokens, Token.Type requestTokenType, Map requestAssertions, Http.Request request);
}
