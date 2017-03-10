package com.bcgdv.play.jwt.util;

import com.bcgdv.jwt.models.Token;
import com.bcgdv.play.jwt.model.AnnotationInfo;

import java.lang.reflect.Method;
import java.util.Optional;
import java.util.Set;

/**
 * A static helper to scan Security Token annotations.
 */
public class JwtAnnotationHelper {

    /**
     * don't use me
     */
    protected JwtAnnotationHelper() {
    }

    /**
     * Check a controller method is annotated anonymous and allows public access. Must be explicitly allowed by whitelisting
     * the controller with @Anonymous. An otherwise empty controller method will be blocked by the filter
     *
     * @param anonymousAnnotationInfo The AnnotationInfo
     * @param className               The class name
     * @param methodName              The method name
     * @return true | false
     */
    public static boolean hasAnonymousAnnotation(AnnotationInfo.Anonymous anonymousAnnotationInfo, String className, String methodName) {
        return hasMethodName(anonymousAnnotationInfo.getAnonymousMethods(), className, methodName)
                || hasClassName(anonymousAnnotationInfo.getAnonymousClasses(),
                className);
    }

    /**
     * Checks for @Secure AnnotationInfo in class or methods. For security purposes, annotate methods over classes
     *
     * @param secure     the annotationInfo
     * @param className  the className to check
     * @param methodName the methodName to check
     * @return true | false if the the annotationInfo contains either
     */
    public static boolean hasSecureAnnotation(AnnotationInfo.Secure secure, String className, String methodName) {
        return hasSecureAnnotationInMethod(secure, className, methodName) ||
                hasSecureAnnotationInClass(secure, className);
    }

    /**
     * Returns arraytype of tokens found for @Secure annotation or nothing
     *
     * @param secure     the annotation info
     * @param className  the class
     * @param methodName the method
     * @return result as Token.Type[]
     */
    public static Optional<Token.Type[]> findTokenTypesForSecureAnnotation(AnnotationInfo.Secure secure, String className, String methodName) {
        if (hasSecureAnnotation(secure, className, methodName)) {
            return Optional.of(findAnnotation(secure, className, methodName));
        }
        return Optional.empty();
    }

    /**
     * finds class or method annotations
     *
     * @param secure     the annotation info
     * @param className  the class
     * @param methodName the method
     * @return results as Token.Type[]
     */
    protected static Token.Type[] findAnnotation(AnnotationInfo.Secure secure, String className, String methodName) {
        if (hasSecureAnnotationInMethod(secure, className, methodName)) {
            return findSecureAnnotationInMethod(secure, className, methodName);
        } else {
            return findSecureAnnotationInClass(secure, className);
        }
    }


    /**
     * Does a set of classes have a class name?
     *
     * @param classes   the classes
     * @param className the classname
     * @return true | false
     */
    protected static boolean hasClassName(Set<Class<?>> classes, String className) {
        for (Class<?> clazz : classes) {
            if (clazz.getName().equals(className)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Does a set of methods have a method name
     *
     * @param methods    the method set
     * @param className  the class
     * @param methodName the method name
     * @return true | false
     */
    protected static boolean hasMethodName(Set<Method> methods, String className, String methodName) {
        for (Method method : methods) {
            if (method.getDeclaringClass().getName().equals(className) && method.getName().equals(methodName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Is a method annotated with @Secure?
     *
     * @param secure     the annotation info
     * @param className  the class
     * @param methodName the method
     * @return true | false
     */
    protected static boolean hasSecureAnnotationInMethod(AnnotationInfo.Secure secure, String className, String methodName) {
        return hasMethodName(secure.getSecureMethods(), className, methodName);
    }

    /**
     * Is a class annotated with @Secure?
     *
     * @param secure    the annotation info
     * @param className the class
     * @return true | false
     */
    protected static boolean hasSecureAnnotationInClass(AnnotationInfo.Secure secure, String className) {
        return hasClassName(secure.getSecureClasses(), className);
    }

    /**
     * Find secure annotation contents in class
     *
     * @param secureAnnotationInfo the annotation info
     * @param className            the class
     * @return the content as Token.Type[]
     */
    protected static Token.Type[] findSecureAnnotationInClass(AnnotationInfo.Secure secureAnnotationInfo, String className) {
        for (Class<?> clazz : secureAnnotationInfo.getSecureClasses()) {
            if (clazz.getName().equals(className)) {
                com.bcgdv.play.jwt.Secure secure = clazz.getDeclaredAnnotation(com.bcgdv.play.jwt.Secure.class);
                return secure.type();
            }
        }
        throw new IllegalArgumentException("Cannot find token for given class " + className);
    }

    /**
     * Find secure annotation contents in method
     *
     * @param secureAnnotationInfo the annotation info
     * @param className            the class
     * @param methodName           the method
     * @return the content as Token.Type[]
     */
    protected static Token.Type[] findSecureAnnotationInMethod(AnnotationInfo.Secure secureAnnotationInfo, String className, String methodName) {
        for (Method method : secureAnnotationInfo.getSecureMethods()) {
            if (method.getDeclaringClass().getName().equals(className) && method.getName().equals(methodName)) {
                com.bcgdv.play.jwt.Secure secure = method.getDeclaredAnnotation(com.bcgdv.play.jwt.Secure.class);
                return secure.type();
            }
        }
        throw new IllegalArgumentException("Cannot find token for given class " + className + " method " + methodName);
    }
}
