/*
 * PublicKeyCache
 */
package com.bcgdv.play.jwt.util;

import javax.inject.Singleton;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Public Key cache keeps a copy of service api pubkeys locally for performance reasons.
 */
@Singleton
public class PublicKeyCache {

    /**
     * I can haz Hashmap
     */
    static protected Map<String, String> cache;

    /**
     * Init with concurrent HashMap cause we're in multithreaded webserver
     */
    public PublicKeyCache() {
        cache = new ConcurrentHashMap<>();
    }

    /**
     * add public key to cache
     * @param context the key context
     * @param key the key as String
     */
    public void addKey(String context, String key) {
        cache.put(context, key);
    }

    /**
     * Get a public key from cache
     * @param context the key context
     * @return the key as String
     */
    public String getKey(String context) {
        return cache.get(context);
    }
}
