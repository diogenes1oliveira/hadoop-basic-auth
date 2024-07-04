package dev.diogenes.hadoop.basicauth;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.security.authentication.server.AuthenticationHandler;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class HadoopBasicAuthenticationHandler implements AuthenticationHandler {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String AUTHORIZATION_SCHEME = "Basic";
    public static final String HTPASSWD_PATH_PROPERTY = "htpasswd.path";
    public static final String REALM_PROPERTY = "realm";
    public static final String DEFAULT_REALM = "LOCALHOST";
    public static final String TYPE = "basic";
    private HtpasswdFile htpasswdFile = null;
    private String realm = null;

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public void init(Properties properties) {
        this.htpasswdFile = new HtpasswdFile(properties.getProperty(HTPASSWD_PATH_PROPERTY, ""));
        this.realm = properties.getProperty(REALM_PROPERTY, DEFAULT_REALM);
    }

    @Override
    public AuthenticationToken authenticate(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Pair<Pair<String, String>, String> basicAuth = extractBasicAuth(request.getHeader(AUTHORIZATION_HEADER));
        String errorMessage = basicAuth.getRight();

        if (errorMessage == null) {
            Pair<String, String> usernameAndPassword = basicAuth.getLeft();
            String username = usernameAndPassword.getLeft();
            String password = usernameAndPassword.getRight();
            HtpasswdFile.CheckResult result = htpasswdFile.parse().check(username, password);
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

    public static Pair<Pair<String, String>, String> extractBasicAuth(String headerValue) {
        String[] headerParts = safeString(headerValue).split("\\s+", 2);

        if (headerParts.length == 0) {
            return Pair.of(null, "no auth found");
        }
        String scheme = headerParts[0].trim();
        if (!AUTHORIZATION_SCHEME.equals(scheme)) {
            return Pair.of(null, "invalid auth scheme");
        }
        if (headerParts.length < 2) {
            return Pair.of(null, "no auth payload");
        }
        String payload = headerParts[1].trim();
        String userAndPassword;
        try {
            byte[] data = Base64.getDecoder().decode(payload);
            userAndPassword = StandardCharsets.US_ASCII.newDecoder().decode(ByteBuffer.wrap(data)).toString();
        } catch (IllegalArgumentException | CharacterCodingException e) {
            return Pair.of(null, "invalid auth payload");
        }

        String[] authParts = safeString(userAndPassword).split(":", 2);
        if (authParts.length != 2) {
            return Pair.of(null, "no username or no password");
        }
        String username = authParts[0];
        String password = authParts[1];
        if (username.isEmpty() || password.isEmpty()) {
            return Pair.of(null, "no username or no password");
        }
        return Pair.of(Pair.of(username, password), null);
    }

    private static String safeString(String nullableString) {
        return Optional.ofNullable(nullableString)
                .orElse("")
                .trim();
    }

}
