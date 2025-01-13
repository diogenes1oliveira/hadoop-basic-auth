package dev.diogenes.hadoop.basicauth;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.file.Files;
import java.nio.file.Path;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class HtpasswdFileTest {
    @TempDir
    static Path tempDir;
    static HtpasswdFile htpasswdFile;

    @BeforeAll
    static void setUp() throws Exception {
        Path tempFile = tempDir.resolve("auth");

        String content = HtpasswdFile.generate("alice", "password") + "\n";
        Files.write(tempFile, content.getBytes(UTF_8));

        htpasswdFile = new HtpasswdFile(tempFile);
    }

    @ParameterizedTest
    @CsvSource({
            "alice, password, OK",
            "alice, wrong, WRONG_PASSWORD",
            "alice, '', WRONG_PASSWORD",
            "bob, password, NOT_FOUND"
    })
    void testValues(String username, String password, HtpasswdFile.CheckResult expected) throws Exception {
        htpasswdFile.refresh();
        assertThat(htpasswdFile.check(username, password), equalTo(expected));
    }
}
