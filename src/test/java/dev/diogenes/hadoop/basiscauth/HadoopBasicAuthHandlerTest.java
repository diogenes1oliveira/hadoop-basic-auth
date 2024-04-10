package dev.diogenes.hadoop.basiscauth;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Properties;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.*;

class HadoopBasicAuthHandlerTest {
    @TempDir
    static Path tempDir;
    static Path htpasswdPath;
    static Properties props;
    static HadoopBasicAuthHandler handler = new HadoopBasicAuthHandler();
    String PASSWORD = "password";

    @BeforeAll
    static void setUp() throws Exception {
        htpasswdPath = tempDir.resolve("htpasswd");
        try (BufferedWriter writer = Files.newBufferedWriter(htpasswdPath)) {
            writer.write("alice:");
            writer.write(BCrypt.withDefaults().hashToString(6, "password".toCharArray()));
            writer.write('\n');

            writer.write("bob:");
            writer.write(BCrypt.withDefaults().hashToString(6, "password".toCharArray()));
            writer.write('\n');
        }
        props = new Properties();
        props.setProperty("htpasswd", htpasswdPath.toString());

        handler.init(props);
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
    void testBadPassword() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.addHeader("Authorization", "Basic " + authEncode("bob", "wrong"));

        assertThrows(AuthenticationException.class, () -> handler.authenticate(request, response));
    }

    @Test
    void testNoAuth() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationToken token = handler.authenticate(request, response);
        assertThat(token, nullValue());
        assertThat(response.getHeader("WWW-Authenticate"), equalTo("Basic"));
        assertThat(response.getStatus(), equalTo(401));
    }

    @Test
    void testMissingUser() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.addHeader("Authorization", "Basic " + authEncode("eve", "password"));

        assertThrows(AuthenticationException.class, () -> handler.authenticate(request, response));
    }

    static String authEncode(String userName, String password) {
        String auth = userName + ":" + password;
        return Base64.getEncoder().encodeToString(auth.getBytes(UTF_8));
    }
}
