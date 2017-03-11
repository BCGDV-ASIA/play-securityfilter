/**
 * AssertionValidator
 */
package com.bcgdv.play.jwt.validation;

import com.bcgdv.jwt.models.Token;
import play.mvc.Http;

import java.util.Map;

/**
 * Iterate over assertions and execute validation
 */
public interface AssertionValidator {

    /**
     * Iterate over validators and pass if all off them return true;
     * @param annotatedTokens the annotated tokens
     * @param requestTokenType the request token type passed in
     * @param requestAssertions the request assertions passed in
     * @param request the actual request
     * @return true | false
     */
    boolean validate(Token.Type[] annotatedTokens, Token.Type requestTokenType, Map requestAssertions, Http.Request request);
}
