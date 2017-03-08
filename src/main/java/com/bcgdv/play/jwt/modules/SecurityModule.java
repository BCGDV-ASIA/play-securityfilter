/*
 * JwtConfigModule
 */
package com.bcgdv.play.jwt.modules;

import com.bcgdv.jwt.models.AsymmetricKeyInfo;
import com.bcgdv.jwt.models.TokenExpiryInfo;
import com.bcgdv.jwt.providers.AsymmetricSecurityKeyProvider;
import com.bcgdv.jwt.providers.SymmetricCipherProvider;
import com.bcgdv.jwt.providers.TokenExpiryInfoProvider;
import com.bcgdv.jwt.services.TokenGenerationService;
import com.bcgdv.jwt.services.TokenGenerationServiceImpl;
import com.bcgdv.play.jwt.validation.HttpRequestValidator;
import com.bcgdv.play.jwt.validation.HttpRequestValidatorJwtAuthorizationHeaderImpl;
import com.bcgdv.play.services.Api;
import com.bcgdv.play.services.ApiFacade;
import com.google.inject.AbstractModule;
import com.google.inject.name.Names;
import com.simonmittag.cryptoutils.SimpleCipher;
import com.simonmittag.cryptoutils.symmetric.CipherFactory;
import com.simonmittag.cryptoutils.symmetric.SimpleSymmetricCipher;

/**
 * Security module binds Guice dependencies and loads as Play module
 */
public class SecurityModule extends AbstractModule {

    /**
     * Configure the Security modules
     */
    @Override
    public void configure() {

        // Token expiry is provided by env variables.
        bind(TokenExpiryInfo.class)
                .toProvider(TokenExpiryInfoProvider.class);

        // RSA keypairs are provided by env variables
        bind(AsymmetricKeyInfo.class)
                .toProvider(AsymmetricSecurityKeyProvider.class);

        // Points to default implementation
        bind(TokenGenerationService.class)
                .to(TokenGenerationServiceImpl.class);

        // Symmetric cipher is initialized by env variables.
        bind(SimpleSymmetricCipher.class)
                .toProvider(SymmetricCipherProvider.class);
        bind(SimpleCipher.class)
                .annotatedWith(Names.named("symmetricCipher"))
                .toInstance(CipherFactory.getInstance());

        // Api binds to standard facade.
        bind(Api.class)
                .to(ApiFacade.class);

        // Points to default implementation
        bind(HttpRequestValidator.class)
                .to(HttpRequestValidatorJwtAuthorizationHeaderImpl.class);
    }
}
