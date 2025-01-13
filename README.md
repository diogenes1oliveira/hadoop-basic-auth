# hadoop-basic-auth

HTTP Basic Auth Implementation for Hadoop Security

## Usage

### Adding to service

```shell
# livy-env.sh
CUSTOM_LIVY_CLASSPATH=./hadoop-basic-auth-0.0.1.jar

# don't forget to include all of Livy's own jars
export LIVY_CLASSPATH="$(
    (
        find "$SPARK_HOME/jars" -name 'log4j-*.jar'
        find "$LIVY_HOME/jars" "$LIVY_HOME/rsc-jars" "$LIVY_HOME/repl_2.12-jars" -name '*.jar'
        echo "$CUSTOM_LIVY_CLASSPATH"
    ) | paste -sd ':'
)"
echo >&2 "\$LIVY_CLASSPATH=$LIVY_CLASSPATH"
```

```properties
# livy.conf
livy.server.auth.type = custom
livy.server.auth.custom.class = org.apache.hadoop.security.authentication.server.AuthenticationFilter
livy.server.auth.custom.param.type = dev.diogenes.hadoop.basicauth.HadoopBasicAuthenticationHandler
livy.server.auth.custom.param.htpasswd.path = .htpasswd
livy.server.auth.custom.param.realm = REALM
livy.server.auth.custom.param.signer.secret.provider = random
```

### Generating the file

```shell
java -cp hadoop-basic-auth-0.0.1-SNAPSHOT-4.jar dev.diogenes.hadoop.basicauth.HtpasswdFile USERNAME <<<"password"
```
