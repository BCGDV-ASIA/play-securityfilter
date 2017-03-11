/*
 * AssertionValidatorModule
 */
package com.bcgdv.play.jwt.modules;

import com.bcgdv.play.jwt.validation.AssertionValidation;
import com.bcgdv.play.jwt.validation.DefaultAssertionValidation;
import com.google.inject.AbstractModule;

/**
 * Module config for AssertionValidation
 */
public class AssertionValidationModule extends AbstractModule {

    /**
     * Configure the AssertionValidation
     */
    @Override
    public void configure() {
        // This always passes
        bind(AssertionValidation.class)
                .to(DefaultAssertionValidation.class);

//      bind(AssertionValidation.class).to(MyAssertionValidation.class);
    }

}
