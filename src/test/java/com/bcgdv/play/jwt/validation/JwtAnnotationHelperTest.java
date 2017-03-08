package com.bcgdv.play.jwt.validation;

import com.bcgdv.play.jwt.model.AnnotationInfo;
import com.bcgdv.play.jwt.util.JwtAnnotationHelper;
import com.google.common.collect.Sets;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * Created by ambalavanan mohan on 17/04/2016.
 */
public class JwtAnnotationHelperTest {

    public static AnnotationInfo.Anonymous emptyAnnonymousAnnotationInfo() {
        return new AnnotationInfo.Anonymous(Sets.newHashSet(), Sets.newHashSet());
    }

    @Test
    public void givenEmptyAnonymousMethodListisInsecureShouldReturnFalse() throws Exception {
        assertThat(JwtAnnotationHelper.hasAnonymousAnnotation(emptyAnnonymousAnnotationInfo(), "Test", "test"), is(false));
    }

    @Test
    public void givenAnonymousMethodSetisInsecureShouldReturnTrue() throws Exception {
        AnnotationInfo.Anonymous anonymousAnnotationInfo =
                new AnnotationInfo.Anonymous(
                        Sets.newHashSet(),
                        Sets.newHashSet(JwtAnnotationHelperTest.class.getMethods()[0]));

        assertThat(
                JwtAnnotationHelper.hasAnonymousAnnotation(
                        anonymousAnnotationInfo, JwtAnnotationHelperTest.class.getName(),
                        JwtAnnotationHelperTest.class.getMethods()[0].getName()),
                is(true));
    }

    @Test
    public void givenAnonymousClassSetIsInsecrueShouldReturnTrue() throws Exception {
        AnnotationInfo.Anonymous anonymousAnnotationInfo =
                new AnnotationInfo.Anonymous(
                        Sets.newHashSet(JwtAnnotationHelperTest.class),
                        Sets.newHashSet());

        assertThat(
                JwtAnnotationHelper.hasAnonymousAnnotation(
                        anonymousAnnotationInfo, JwtAnnotationHelperTest.class.getName(),
                        JwtAnnotationHelperTest.class.getMethods()[0].getName()),
                is(true));
    }


    @Test
    public void givenEmptyRoleshasRolesShouldReturnFalse() throws Exception {
        AnnotationInfo.Secure secure =
                new AnnotationInfo.Secure(Sets.newHashSet(), Sets.newHashSet());

        assertThat(JwtAnnotationHelper.hasSecureAnnotation(secure, "Test", "test"), is(false));
    }

    @Test
    public void givenRolesInMethodhasRolesShouldReturnTrue() throws Exception {
        AnnotationInfo.Secure secure =
                new AnnotationInfo.Secure(
                        Sets.newHashSet(),
                        Sets.newHashSet(this.getClass().getMethods()[0]));

        assertThat(
                JwtAnnotationHelper.hasSecureAnnotation(
                        secure, this.getClass().getName(),
                        this.getClass().getMethods()[0].getName()),
                is(true));
    }

    @Test
    public void givenRolesInClassasRolesShouldReturnTrue() throws Exception {
        AnnotationInfo.Secure secure = new AnnotationInfo.Secure(Sets.newHashSet(this.getClass()),
                Sets.newHashSet());
        assertThat(JwtAnnotationHelper.hasSecureAnnotation(secure, this.getClass().getName(), null),
                is(true));
    }


    @Test
    public void getTokenTypesIfExistOnRoleAnnotation() throws Exception {

    }

    @Test
    public void extractToken() throws Exception {

    }


    @Test
    public void extractTokenFromClass() throws Exception {

    }

    @Test
    public void extractTokenFromMethod() throws Exception {

    }

}