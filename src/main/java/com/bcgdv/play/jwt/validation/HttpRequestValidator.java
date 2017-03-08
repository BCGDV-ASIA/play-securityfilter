/**
 * SecurityService
 */
package com.bcgdv.play.jwt.validation;

import play.mvc.Http;

import java.util.Optional;

/**
 * Provides methods to secure requests via HTTP Header inspection
 */
public interface HttpRequestValidator {

    /**
     * Validate a request by inspecting it's headers
     *
     * @param requestHeader The current http request header
     * @return Optional<String> with validation errors. Returns empty if request has no validation
     * errors, "no news is good news"
     */
    Optional<String> validate(Http.RequestHeader requestHeader);
}
