package com.bcgdv.play.jwt.model;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.Set;

/**
 * Facade for all anonyous and roles annotation info.
 */
public final class AnnotationInfo implements Serializable {


    /**
     * Has @AnonymousAnnotationInfo
     */
    protected Anonymous anonymousAnnotationInfo;

    /**
     * Has @RolesAnnotationIno
     */
    protected Secure secure;


    /**
     * Build with @AnonymousAnnotationInfo and @RolesAnnotationInfo
     *
     * @param anonymousAnnotationInfo the @AnonymousAnnotationInfo
     * @param secure                  the @RolesAnnotationInfo
     */
    public AnnotationInfo(Anonymous anonymousAnnotationInfo,
                          Secure secure) {
        this.anonymousAnnotationInfo = anonymousAnnotationInfo;
        this.secure = secure;
    }

    /**
     * Get @AnonymousAnnotationInfo
     *
     * @return the @AnonymousAnnotationInfo
     */
    public Anonymous getAnonymousAnnotationInfo() {
        return anonymousAnnotationInfo;
    }

    /**
     * Get @RolesAnnotationInfo
     *
     * @return the @RolesAnnotationInfo
     */
    public Secure getSecure() {
        return secure;
    }

    /**
     * Facade for Annotation Info for @Anonymous class and method annotations.
     */
    public static final class Anonymous implements Serializable {

        /**
         * Has anonymous classes
         */
        protected Set<Class<?>> anonymousClasses;

        /**
         * Has anonymous methods
         */
        protected Set<Method> anonymousMethods;

        /**
         * Build with Set of Classes and Methods
         *
         * @param anonymousClasses the classes
         * @param anonymousMethods the methods
         */
        public Anonymous(Set<Class<?>> anonymousClasses, Set<Method> anonymousMethods) {
            this.anonymousClasses = anonymousClasses;
            this.anonymousMethods = anonymousMethods;
        }

        /**
         * Get the anonymous tagged classes.
         *
         * @return a Set of classes
         */
        public Set<Class<?>> getAnonymousClasses() {
            return anonymousClasses;
        }

        /**
         * get the anonymous tagged methods
         *
         * @return a Set of methods
         */
        public Set<Method> getAnonymousMethods() {
            return anonymousMethods;
        }
    }

    /**
     * Facade for Annotation Info for @Secure class and method annotations.
     */
    public static class Secure implements Serializable {

        /**
         * Has Secure Classes
         */
        protected Set<Class<?>> secureClasses;


        /**
         * And Secure Methods
         */
        protected Set<Method> secureMethods;


        /**
         * Create with Secure classes and methods
         *
         * @param rolesClasses the classes
         * @param rolesMethods the methods
         */
        public Secure(Set<Class<?>> rolesClasses, Set<Method> rolesMethods) {
            this.secureClasses = rolesClasses;
            this.secureMethods = rolesMethods;
        }

        /**
         * Get the secure classes
         *
         * @return the classes
         */
        public Set<Class<?>> getSecureClasses() {
            return secureClasses;
        }


        /**
         * Get the secure methods
         *
         * @return the methods
         */
        public Set<Method> getSecureMethods() {
            return secureMethods;
        }
    }
}
