package com.bcgdv.play.jwt.validation;

import com.bcgdv.play.jwt.Anonymous;
import com.bcgdv.play.jwt.Secure;
import com.bcgdv.play.jwt.model.AnnotationInfo;
import com.bcgdv.play.jwt.model.Play;
import com.bcgdv.play.jwt.util.JwtAnnotationHelper;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.scanners.TypeAnnotationsScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.Environment;
import play.mvc.Http;
import play.routing.Router;

import java.net.URL;
import java.util.Collection;
import java.util.Optional;

/**
 * Validates incoming HTTP requests for JWT Tokens. Note this class lazy loads and initializes
 * dependencies that Guice cannot deliver because of a bug.
 */
@Singleton
public class HttpRequestValidatorJwtAuthorizationHeaderImpl implements HttpRequestValidator {

    protected Logger logger = LoggerFactory.getLogger(HttpRequestValidatorJwtAuthorizationHeaderImpl.class);

    /**
     * Error messages
     */
    protected static final String SECURE_REQUEST_VALIDATION_FAILURE = "request detected as secureable for URI %s, but failed token validation, cause: %s";
    protected static final String NONSECURE_REQUEST = "request detected as not secureable, no token required for URI: ";

    /**
     * has service to validate integrity of jwt
     */
    protected JwtIntegrityValidationService jwtIntegrityValidationService;

    /**
     * has service to validate jwt payload
     */
    protected JwtPayloadValidationService jwtPayloadValidationService;

    /**
     * lazy loads reflections at runtime
     */
    protected Reflections reflections;

    /**
     * has access to environment for play classloader
     */
    protected Environment environment;


    /**
     * Build with services and environment
     *
     * @param jwtIntegrityValidationService to check token integrity
     * @param jwtPayloadValidationService   to check token payload
     * @param environment                   to access classloader
     */
    @Inject
    public HttpRequestValidatorJwtAuthorizationHeaderImpl(JwtIntegrityValidationService jwtIntegrityValidationService,
                                                          JwtPayloadValidationService jwtPayloadValidationService,
                                                          Environment environment) {
        this.jwtIntegrityValidationService = jwtIntegrityValidationService;
        this.jwtPayloadValidationService = jwtPayloadValidationService;
        this.environment = environment;
    }


    /**
     * Creates Annotation info configuration by scanning the specified controller package
     * for @Anonymous and @Secure tags
     *
     * @return the AnnotationInfo
     */
    public AnnotationInfo filterAnnotationInfo() {
        AnnotationInfo.Anonymous anonymousAnnotationInfo =
                new AnnotationInfo.Anonymous(
                        this.getReflections()
                                .getTypesAnnotatedWith(Anonymous.class),
                        this.getReflections()
                                .getMethodsAnnotatedWith(Anonymous.class));

        AnnotationInfo.Secure secure =
                new AnnotationInfo.Secure(
                        this.getReflections()
                                .getTypesAnnotatedWith(Secure.class),
                        this.getReflections()
                                .getMethodsAnnotatedWith(Secure.class));

        return new AnnotationInfo(anonymousAnnotationInfo, secure);
    }


    /**
     * Validate request by looking for and validating contents of JWT token.
     *
     * @param requestHeader The current http request header
     * @return empty String for success or error message included.
     */
    @Override
    public Optional<String> validate(Http.RequestHeader requestHeader) {
        try {
            AnnotationInfo filterAnnotationInfo = filterAnnotationInfo();
            String className = requestHeader.tags().get(Router.Tags.ROUTE_CONTROLLER);
            String methodName = requestHeader.tags().get(Router.Tags.ROUTE_ACTION_METHOD);

            if (requestIsNotForAPlayControllerButAResource(className, methodName)) {
                logger.debug(NONSECURE_REQUEST + requestHeader.uri());
                return Optional.empty();
            }

            if (JwtAnnotationHelper.hasAnonymousAnnotation(
                    filterAnnotationInfo.getAnonymousAnnotationInfo(),
                    className,
                    methodName)) {
                logger.debug(NONSECURE_REQUEST + requestHeader.uri());
                return Optional.empty();
            } else {
                jwtIntegrityValidationService
                        .requestHasWellFormedToken(requestHeader);
                jwtPayloadValidationService
                        .validateJwtPayload(requestHeader, filterAnnotationInfo);
                return Optional.empty();
            }
        } catch (Exception e) {
            String message = String.format(
                    SECURE_REQUEST_VALIDATION_FAILURE,
                    requestHeader.uri(),
                    e.getMessage());
            logger.warn(message);
            return Optional.of(message);
        }
    }


    /**
     * Requests for resources have null class and method names as Tags, because only controllers
     * are annotated. Allows URLs that map to other things than controllers to pass
     *
     * @param className  The class name
     * @param methodName The method name
     * @return true | false
     */
    protected boolean requestIsNotForAPlayControllerButAResource(String className, String methodName) {
        return className == null && methodName == null;
    }


    /**
     * Lazy loading of reflections at runtime, to circumvent the Guice classloader problem.
     *
     * @return the reflections
     */
    public Reflections getReflections() {
        if (this.reflections == null) {
            this.reflections = reflections();
        }
        return this.reflections;
    }


    /**
     * Provides a Reflections configuration that reads Annotations from classes
     * and methods in the play controllers package and below.
     *
     * @return Reflections
     */
    protected Reflections reflections() {
        ConfigurationBuilder configurationBuilder =
                new ConfigurationBuilder()
                        .setUrls(getFilterConfigurationUrls())
                        .setScanners(new TypeAnnotationsScanner(),
                                new MethodAnnotationsScanner(),
                                new SubTypesScanner());
        configurationBuilder.setClassLoaders(new ClassLoader[]{playClassLoader()});
        return new Reflections(configurationBuilder);
    }


    /**
     * Get classpath for controllers
     *
     * @return as url collection
     */
    protected Collection<URL> getFilterConfigurationUrls() {
        return ClasspathHelper
                .forPackage(
                        playControllerPackage(),
                        playClassLoader());
    }


    /**
     * Get play classloader
     *
     * @return as Classloader
     */
    protected ClassLoader playClassLoader() {
        return environment.classLoader();
    }


    /**
     * Fetch the configured play controller package to scan for annotations.
     *
     * @return as String
     */
    protected String playControllerPackage() {
        String controllerPackage = System.getProperty(Play.CONTROLLER_PACKAGE);
        if (controllerPackage == null) {
            controllerPackage = System.getenv(Play.CONTROLLER_PACKAGE);
        }
        if (controllerPackage == null) {
            controllerPackage = Play.DEFAULT_CONTROLLER_PACKAGE;
        }
        return controllerPackage;
    }
}
