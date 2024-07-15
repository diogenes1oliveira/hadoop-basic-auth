package dev.diogenes.hadoop.basicauth;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HtpasswdFile {
    public static final Pattern LINE_PATTERN = Pattern.compile("^(?<user>[a-z][a-z0-9-]+):(?<encrypted>.+)$");
    private static final Logger LOGGER = LoggerFactory.getLogger(HtpasswdFile.class);
    private static final char[] EMPTY_CHARS = new char[0];
    private final Path htpasswdPath;
    private final Map<String, char[]> userPasswords = new ConcurrentHashMap<>(1);

    public HtpasswdFile(Path htpasswdPath) {
        this.htpasswdPath = htpasswdPath;
    }

    public HtpasswdFile refresh() {
        Map<String, char[]> newUserPasswords = new HashMap<>();

        try (BufferedReader reader = Files.newBufferedReader(htpasswdPath)) {
            do {
                String line = reader.readLine();
                if (line == null) {
                    break;
                }
                Matcher m = LINE_PATTERN.matcher(line);
                if (!m.matches()) {
                    continue;
                }

                String user = m.group("user");
                char[] encryptedPassword = m.group("encrypted").toCharArray();
                BCrypt.Result result = BCrypt.verifyer().verify(EMPTY_CHARS, encryptedPassword);
                if (result.validFormat) {
                    newUserPasswords.put(m.group("user"), encryptedPassword);
                } else {
                    throw new IOException("invalid password for user '" + user + '"');
                }
            } while (true);
        } catch (IOException e) {
            LOGGER.warn("failed to read htpasswd path", e);
        }

        // so it's thread safe
        userPasswords.putAll(newUserPasswords);
        userPasswords.keySet().retainAll(newUserPasswords.keySet());

        return this;
    }

    public CheckResult check(String username, String password) {
        char[] encryptedPassword = userPasswords.get(username);
        if (encryptedPassword == null) {
            return CheckResult.NOT_FOUND;
        }

        BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), encryptedPassword);
        if (!result.verified) {
            return CheckResult.WRONG_PASSWORD;
        }

        return CheckResult.OK;
    }

    public enum CheckResult {
        OK,
        NOT_FOUND,
        WRONG_PASSWORD
    }
}
