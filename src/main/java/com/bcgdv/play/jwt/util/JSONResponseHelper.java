/*
 * JSONResponseHelper
 */
package com.bcgdv.play.jwt.util;

import com.fasterxml.jackson.databind.node.ObjectNode;
import play.libs.Json;
import play.mvc.Result;

import java.util.HashMap;
import java.util.Map;

import static play.mvc.Results.status;

/**
 * Utility class to generate JSON default responses for downstream
 */
public class JSONResponseHelper {


    /**
     * Has a map of valid response codes
     */
    public static Map<String, String> httpResponseCodes;


    /**
     * that is statically initialized with content
     */
    static {
        httpResponseCodes = new HashMap<String, String>();
        httpResponseCodes.put("200", "HTTP 200 - Ok");
        httpResponseCodes.put("201", "HTTP 201 - Resource has been created");
        httpResponseCodes.put("400", "HTTP 400 - Invalid request message");
        httpResponseCodes.put("401", "HTTP 401 - You don't have the necessary credentials.");
        httpResponseCodes.put("403", "HTTP 403 - You don't have permission to access this resource.");
        httpResponseCodes.put("404", "HTTP 404 - Resource not found");
        httpResponseCodes.put("408", "HTTP 408 - Request Timeout");
        httpResponseCodes.put("500", "HTTP 500 - Unable to process this request");
    }


    /**
     * 200 OK
     *
     * @return as JSON Play Result
     */
    public static Result okAsJSON() {
        return resultAsJSON("200");
    }


    /**
     * 201 Created
     *
     * @return as JSON Play Result
     */
    public static Result createdAsJSON() {
        return resultAsJSON("201");
    }


    /**
     * 400 Bad request
     *
     * @return as JSON Play Result
     */
    public static Result badAsJSON() {
        return resultAsJSON("400");
    }


    /**
     * 401 Unauthenticated
     *
     * @return as JSON Play Result
     */
    public static Result unauthenticatedAsJSON() {
        return resultAsJSON("401");
    }


    /**
     * 403 forbidden
     * * @return as JSON Play Result
     */
    public static Result forbiddenAsJSON() {
        return resultAsJSON("403");
    }


    /**
     * 404 not found
     *
     * @return as JSON Play Result
     */
    public static Result notFoundAsJSON() {
        return resultAsJSON("404");
    }


    /**
     * 408 client timeout
     *
     * @return as JSON Play Result
     */
    public static Result timeoutAsJSON() {
        return resultAsJSON("408");
    }


    /**
     * 500 server error
     *
     * @return as JSON Play Result
     */
    public static Result errorAsJSON() {
        return resultAsJSON("500");
    }


    /**
     * Create a JSON object node with result and return as Play API object.
     *
     * @param httpResponseCode the response code
     * @return as JSON Play Result
     */
    protected static Result resultAsJSON(String httpResponseCode) {
        ObjectNode result = Json.newObject();
        result.put("status", httpResponseCode);
        result.put("message", httpResponseCodes.get(httpResponseCode));
        return status(Integer.parseInt(httpResponseCode), result);
    }
}
