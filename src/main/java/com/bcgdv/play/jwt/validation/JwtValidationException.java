/*
 * JwtValidationException
 */
package com.bcgdv.play.jwt.validation;

/**
 * JwtValidationException
 */
public class JwtValidationException extends RuntimeException {


    /**
     * Default
     */
    public JwtValidationException() {
        super();
    }


    /**
     * With Exception
     *
     * @param e as nested Exception
     */
    public JwtValidationException(Exception e) {
        super(e);
    }


    /**
     * With Message
     *
     * @param message as String
     */
    public JwtValidationException(String message) {
        super(message);
    }
}
