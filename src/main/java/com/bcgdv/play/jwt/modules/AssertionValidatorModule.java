/*
 * AssertionValidatorModule
 */
package com.bcgdv.play.jwt.modules;

import com.bcgdv.play.jwt.validation.AssertionValidation;
import com.bcgdv.play.jwt.validation.AssertionValidator;
import com.bcgdv.play.jwt.validation.AssertionValidatorImpl;
import com.google.inject.AbstractModule;

/**
 * Module config for AssertionValidator
 */
public class AssertionValidatorModule extends AbstractModule {

    /**
     * Configure the AssertionValidator
     */
    @Override
    public void configure() {
        // Points to default impl.
        bind(AssertionValidator.class)
                .to(AssertionValidatorImpl.class);

//        try {
//            bind(AssertionValidation.class).to(MyAssertionValidation.class);
//            bind(AssertionValidator.class).toConstructor(
//                    AssertionValidatorImpl.class.getConstructor(AssertionValidation.class)
//            );
//        } catch (NoSuchMethodException e) {
//            throw new RuntimeException("unable to bind assertion validation");
//        }
    }

}
