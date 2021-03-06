package com.bcgdv.play.jwt.modules;

import com.bcgdv.play.jwt.Anonymous;
import com.bcgdv.play.jwt.Secure;
import com.bcgdv.play.jwt.model.AnnotationInfo;
import com.google.inject.Inject;
import org.reflections.Reflections;
import play.Environment;

import javax.inject.Provider;

/**
 * Provider implementation for @AnnotationInfo
 */
@Deprecated
public class AnnotationInfoProvider implements Provider<AnnotationInfo> {

    /**
     * Has reflections for class and method introspection of annotations
     */
    protected Reflections reflections;
    protected Environment environment;

    /**
     * Called by Guide. Pass in Reflections that point at Play classloader for controllers
     * @param reflections the Reflections
     * @param environment the environment
     */
    @Inject
    public AnnotationInfoProvider(Reflections reflections, Environment environment) {
        this.reflections = reflections;
        this.environment = environment;
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
