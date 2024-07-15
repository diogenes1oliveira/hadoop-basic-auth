# hadoop-basic-auth

HTTP Basic Auth Implementation for Hadoop Security

## Usage


```shell
# livy-env.sh
export LIVY_CLASSPATH=...:hadoop-basic-auth-0.0.1.jar
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
