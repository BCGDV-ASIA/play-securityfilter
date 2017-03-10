package com.bcgdv.play.jwt;

import com.bcgdv.jwt.models.Token;
import com.bcgdv.play.jwt.validation.JwtValidationPlayAction;
import play.mvc.With;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Secure your controller method with the @Secure token, specifying a token type. This token must be present in the
 * http request while @SecurityHeaderInterceptor filter is active.
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@With(JwtValidationPlayAction.class)
public @interface Secure {

    /**
     * Has multiple token types, either of which may be present
     *
     * @return as Token.Type[]
     */
    Token.Type[] type() default {Token.Type.NONE};
}
