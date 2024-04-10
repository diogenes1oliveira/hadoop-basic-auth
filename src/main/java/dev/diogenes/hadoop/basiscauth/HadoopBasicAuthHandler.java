package dev.diogenes.hadoop.basiscauth;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCryptParser;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationHandler;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;

public class HadoopBasicAuthHandler implements AuthenticationHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(HadoopBasicAuthHandler.class);

    public static final Pattern LINE_PATTERN = Pattern.compile("^(?<user>[a-z][a-z0-9-]+):(?<encrypted>.+)$");
    private static final String AUTHORIZATION_SCHEME = "Basic";
    public static final String TYPE = "basic";
    private String htpasswdPath = "";

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public void init(Properties properties) throws ServletException {
        this.htpasswdPath = properties.getProperty("htpasswd", "");
    }


    @Override
    public void destroy() {
        // nothing to do
    }

    @Override
    public boolean managementOperation(AuthenticationToken token, HttpServletRequest request, HttpServletResponse response) {
        return true;
    }

    private Map<String, String> readHtpasswd() throws IOException {
        Map<String, String> users = new HashMap<>();

        try (BufferedReader reader = Files.newBufferedReader(Paths.get(htpasswdPath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher m = LINE_PATTERN.matcher(line);
                if (m.matches()) {
                    users.put(m.group("user"), m.group("encrypted"));
                }
            }

            return users;
        }
    }

    private AuthenticationToken authenticateUser(String userName, String password) throws AuthenticationException, IOException {
        if (userName == null || userName.isEmpty()) {
            throw new AuthenticationException("Error validating user: a null or blank username has been provided");
        }
        if (password == null || password.isEmpty()) {
            throw new AuthenticationException("Error validating user: a null or blank password has been provided");
        }

        Map<String, String> users = readHtpasswd();
        String encryptedPassword = users.get(userName);
        if (encryptedPassword == null || encryptedPassword.isEmpty()) {
            throw new AuthenticationException("Error validating user: username not found in database");
        }

        BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), encryptedPassword.toCharArray());
        if (!result.validFormat) {
            LOGGER.warn(result.formatErrorMessage);
            throw new IOException("invalid encrypted password in htpasswd file");
        }

        if (!result.verified) {
            throw new AuthenticationException("Error validating user: password does not match");
        }

        return new AuthenticationToken(userName, userName, TYPE);
    }

    @Override
    public AuthenticationToken authenticate(HttpServletRequest request, HttpServletResponse response) throws
            IOException, AuthenticationException {
        String authorization = request.getHeader("Authorization");
        AuthenticationToken token = null;

        if (authorization != null && authorization.regionMatches(true, 0, AUTHORIZATION_SCHEME, 0, AUTHORIZATION_SCHEME.length())) {
            authorization = authorization.substring(AUTHORIZATION_SCHEME.length()).trim();
            Base64.Decoder decoder = Base64.getDecoder();
            String[] credentials = new String(decoder.decode(authorization), StandardCharsets.UTF_8).split(":", 2);

            if (credentials.length == 2) {
                LOGGER.debug("Authenticating [{}] user", credentials[0]);
                token = this.authenticateUser(credentials[0], credentials[1]);
                response.setStatus(HttpServletResponse.SC_OK);
            }
        } else {
            response.setHeader("WWW-Authenticate", "Basic");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            if (authorization == null) {
                LOGGER.trace("Basic auth starting");
            } else {
                LOGGER.warn("Authorization does not start with Basic : {}", authorization);
            }
        }

        return token;
    }
}
