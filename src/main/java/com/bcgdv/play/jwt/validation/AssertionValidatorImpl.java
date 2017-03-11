/*
 * AssertionValidatorImpl
 */
package com.bcgdv.play.jwt.validation;

import com.bcgdv.jwt.models.Token;
import play.mvc.Http;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Iterate over assertions and execute validation
 */
@Singleton
public class AssertionValidatorImpl implements AssertionValidator {

    /**
     * Has AssertionValidators that are iterated over.
     */
    protected List<AssertionValidation> assertionValidations;

    /**
     * Default
     */
    public AssertionValidatorImpl() {
        this.assertionValidations = new ArrayList<>();
    }

    /**
     * Create with single validator
     * @param assertionValidation the assertion validation
     */
    @Inject
    public AssertionValidatorImpl(AssertionValidation assertionValidation) {
        this.assertionValidations = new ArrayList<>();
        if(assertionValidation!=null) {
            this.assertionValidations.add(assertionValidation);
        }
    }

    /**
     * Create with list of validators
     * @param assertionValidations the validations
     */
    public AssertionValidatorImpl(List<AssertionValidation> assertionValidations) {
        if (assertionValidations!=null) {
            this.assertionValidations = assertionValidations;
        } else {
            this.assertionValidations = new ArrayList<>();
        }
    }

    /**
     * Iterate over validators and pass if all off them return true;
     * @param annotatedTokens the annotated tokens
     * @param requestTokenType the request token type passed in
     * @param requestAssertions the request assertions passed in
     * @param request the actual request
     * @return true | false
     */
    @Override
    public boolean validate(Token.Type[] annotatedTokens, Token.Type requestTokenType, Map requestAssertions, Http.Request request) {
        boolean validated = true;
        for(AssertionValidation assertionValidation : assertionValidations) {
            validated &= assertionValidation.with(annotatedTokens, requestTokenType, requestAssertions, request);
        }
        return validated;
    }
}
