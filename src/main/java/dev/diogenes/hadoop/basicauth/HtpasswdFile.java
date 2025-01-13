package dev.diogenes.hadoop.basicauth;

import at.favre.lib.crypto.bcrypt.BCrypt;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HtpasswdFile {
    public static final Pattern LINE_PATTERN = Pattern.compile("^(?<user>[a-z][a-z0-9-]+):(?<encrypted>.+)$");
    private static final char[] EMPTY_CHARS = new char[0];
    private final Path htpasswdPath;
    private final Map<String, char[]> userPasswords = new ConcurrentHashMap<>(1);

    public HtpasswdFile(Path htpasswdPath) {
        this.htpasswdPath = htpasswdPath;
    }

    public HtpasswdFile refresh() throws IOException {
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

    public static String generate(String username, String password) {
        return username + ':' + BCrypt.withDefaults().hashToString(12, password.toCharArray());
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: HtpasswdFile <username>");
            System.exit(1);
        }

        String username = args[0];
        if (username.isEmpty()) {
            System.err.println("no username specified");
            System.exit(1);
        }
        String password;

        if (System.console() != null) {
            password = new String(System.console().readPassword("Password: ")).trim();
        } else {
            Scanner scanner = new Scanner(System.in);
            if (scanner.hasNextLine()) {
                password = new Scanner(System.in).nextLine().trim();
            } else {
                password = "";
            }
        }

        if (password.isEmpty()) {
            System.err.println("no password specified");
            System.exit(1);
        }

        System.out.println(generate(username, password));
    }

    public enum CheckResult {
        OK,
        NOT_FOUND,
        WRONG_PASSWORD
    }
}
