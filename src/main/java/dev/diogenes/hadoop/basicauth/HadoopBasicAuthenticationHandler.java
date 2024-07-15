package dev.diogenes.hadoop.basicauth;

import org.apache.commons.lang3.tuple.Triple;
import org.apache.hadoop.security.authentication.server.AuthenticationHandler;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Properties;

import static java.util.Optional.ofNullable;

public class HadoopBasicAuthenticationHandler implements AuthenticationHandler {
    public static final String HTPASSWD_PATH_PROPERTY = "htpasswd.path";
    public static final String REALM_PROPERTY = "realm";
    public static final String DEFAULT_REALM = "LOCALHOST";
    public static final String TYPE = "basic";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String AUTHORIZATION_SCHEME = "Basic";
    private HtpasswdFile htpasswdFile = null;
    private String realm = null;

    public static Triple<String, String, String> extractBasicAuth(String headerValue) {
        String[] headerParts = ofNullable(headerValue).orElse("").trim().split("\\s+", 2);

        String scheme = headerParts[0].trim();
        if (!AUTHORIZATION_SCHEME.equals(scheme)) {
            return Triple.of("invalid auth scheme", null, null);
        }
        if (headerParts.length < 2) {
            return Triple.of("no auth payload", null, null);
        }
        String payload = headerParts[1].trim();
        String userAndPassword;
        try {
            byte[] data = Base64.getDecoder().decode(payload);
            userAndPassword = StandardCharsets.US_ASCII.newDecoder().decode(ByteBuffer.wrap(data)).toString();
        } catch (IllegalArgumentException | CharacterCodingException e) {
            return Triple.of("invalid auth payload", null, null);
        }

        String[] authParts = userAndPassword.split(":", 2);
        if (authParts.length != 2) {
            return Triple.of("no username or no password", null, null);
        }
        String username = authParts[0];
        String password = authParts[1];
        if (username.isEmpty() || password.isEmpty()) {
            return Triple.of("no username or no password", null, null);
        }
        return Triple.of(null, username, password);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public void init(Properties properties) {
        Path htpasswdPath = Paths.get(properties.getProperty(HTPASSWD_PATH_PROPERTY, ".htpasswd"));
        this.htpasswdFile = new HtpasswdFile(htpasswdPath);
        this.realm = properties.getProperty(REALM_PROPERTY, DEFAULT_REALM);
    }

    @Override
    public AuthenticationToken authenticate(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Triple<String, String, String> extractedBasicAuth = extractBasicAuth(request.getHeader(AUTHORIZATION_HEADER));
        String errorMessage = extractedBasicAuth.getLeft();

        if (errorMessage == null) {
            String username = extractedBasicAuth.getMiddle();
            String password = extractedBasicAuth.getRight();
            HtpasswdFile.CheckResult result = htpasswdFile.refresh().check(username, password);
            switch (result) {
                case OK:
                    String principal = username + "@" + realm;
                    return new AuthenticationToken(username, principal, TYPE);
                case NOT_FOUND:
                    errorMessage = "no such user";
                    break;
                case WRONG_PASSWORD:
                    errorMessage = "wrong password";
                    break;
            }
        }

        response.setHeader("WWW-Authenticate", "Basic " + realm);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, errorMessage);
        return null;
    }

    @Override
    public void destroy() {
        // nothing to do
    }

    @Override
    public boolean managementOperation(AuthenticationToken token, HttpServletRequest request, HttpServletResponse response) {
        return true;
    }

}
