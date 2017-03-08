package com.bcgdv.play.jwt;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The @Anonymous token allows your play controller method to execute without having a JWT token in the http
 * Authorization header while @SecurityHeaderInterceptor filter is active.
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface Anonymous {
}
