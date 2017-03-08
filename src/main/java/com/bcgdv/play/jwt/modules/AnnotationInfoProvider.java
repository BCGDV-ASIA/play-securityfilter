package com.bcgdv.play.jwt.modules;

import com.bcgdv.play.jwt.model.AnnotationInfo;
import com.google.inject.Inject;
import org.reflections.Reflections;

import javax.inject.Provider;

/**
 * Provider implementation for @AnnotationInfo
 */
public class AnnotationInfoProvider implements Provider<AnnotationInfo> {

    /**
     * Has reflections for class and method introspection of annotations
     */
    protected Reflections reflections;

    /**
     * Called by Guide. Pass in Reflections that point at Play classloader for controllers
     * @param reflections the Reflections
     */
    @Inject
    public AnnotationInfoProvider(Reflections reflections) {
        this.reflections = reflections;
    }

    /**
     * Implement provider method
     * @return AnnotationInfo
     */
    @Override
    public AnnotationInfo get() {
        AnnotationInfo.Anonymous anonymousAnnotationInfo =
                new AnnotationInfo.Anonymous(
                        reflections.getTypesAnnotatedWith(com.bcgdv.play.jwt.Anonymous.class),
                        reflections.getMethodsAnnotatedWith(com.bcgdv.play.jwt.Anonymous.class));

        AnnotationInfo.Secure secure =
                new AnnotationInfo.Secure(
                        reflections.getTypesAnnotatedWith(com.bcgdv.play.jwt.Secure.class),
                        reflections.getMethodsAnnotatedWith(com.bcgdv.play.jwt.Secure.class));

        return new AnnotationInfo(anonymousAnnotationInfo, secure);

    }
}
