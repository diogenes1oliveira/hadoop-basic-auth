package dev.diogenes.hadoop.basicauth;

import org.apache.commons.lang3.tuple.Triple;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.HttpServletResponse;
import java.net.URL;
import java.util.Base64;
import java.util.Properties;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

class HadoopBasicAuthenticationHandlerTest {
    static final String HTPASSWD_TEST_RESOURCE = "htpasswd";
    static Properties props;
    static HadoopBasicAuthenticationHandler handler = new HadoopBasicAuthenticationHandler();

    @BeforeAll
    static void setUp() throws Exception {
        URL resource = HadoopBasicAuthenticationHandlerTest.class.getClassLoader().getResource(HTPASSWD_TEST_RESOURCE);
        String htpasswdPath = requireNonNull(resource).getFile();

        props = new Properties();
        props.setProperty("htpasswd.path", htpasswdPath);

        handler.init(props);
    }

    static String authEncode(String userName, String password) {
        String auth = userName + ":" + password;
        return Base64.getEncoder().encodeToString(auth.getBytes(UTF_8));
    }

    @Test
    void testGoodPassword() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.addHeader("Authorization", "Basic " + authEncode("bob", "password"));

        AuthenticationToken token = handler.authenticate(request, response);
        assertThat(token.getUserName(), equalTo("bob"));
    }

    @Test
    void testBadPassword() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.addHeader("Authorization", "Basic " + authEncode("bob", "wrong"));
        AuthenticationToken token = handler.authenticate(request, response);

        assertThat(token, is(nullValue()));
        assertThat(response.getStatus(), equalTo(HttpServletResponse.SC_UNAUTHORIZED));
    }

    @Test
    void testNoAuth() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationToken token = handler.authenticate(request, response);
        assertThat(token, nullValue());
        assertThat(response.getHeader("WWW-Authenticate"), equalTo("Basic LOCALHOST"));
        assertThat(response.getStatus(), equalTo(401));
    }

    @Test
    void testMissingUser() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.addHeader("Authorization", "Basic " + authEncode("eve", "password"));
        AuthenticationToken token = handler.authenticate(request, response);

        assertThat(token, is(nullValue()));
        assertThat(response.getStatus(), equalTo(HttpServletResponse.SC_UNAUTHORIZED));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "Bearer token",
            "Invalid",
            "Basic",
            "Basic  =",
            "Basic invalid",
            "Basic dXNlcg==", // "user"
            "Basic dXNlcjo=", // "user:"
            "Basic OnBhc3N3b3Jk", // ":password"
    })
    @NullSource
    void extractBasicAuth_ShouldReturnErrors(String headerValue) {
        Triple<String, String, String> actual = HadoopBasicAuthenticationHandler.extractBasicAuth(headerValue);

        assertThat(actual.getLeft(), is(not(emptyOrNullString())));
        assertThat(actual.getMiddle(), is(nullValue()));
        assertThat(actual.getRight(), is(nullValue()));
    }
}
