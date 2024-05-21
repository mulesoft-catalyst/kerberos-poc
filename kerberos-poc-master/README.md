# MuleSoft Kerberos Authentication

## Summary
This MuleSoft project details how to acheive Kerberos authentication in both HTTP requests and Database interactions. This solution works on both Linux and Cloudhub deployments.

## Project Details

### login.conf
Location: src/main/resources/kerberos-configurations
Description: Generic file that is used in the Kerberos Authentication file. No changes needed to incorporate into project

### krb5.conf
Location: src/main/resources/kerberos-configurations
Description: Kerberos authentication file that will need to be filled out by user. All properties contained in ${} will need to be updated with the relevant domain details. The secondary realm is not required and can be deleted.

### KerberosHttpURLConnection.java
Location: src/main/java/com.newrez.kerberos
Description: Java class that will facilitate the HTTP authentication and request using Kerberos. You can call this class with the invoke static connector found in the project

### Required JVM Parameters
Description: JVM arguments needed to access the conf files at project deployment time. 

- -Djava.security.auth.login.config=<localPath>/login.conf 
- -Djava.security.krb5.conf=<localPath>/krb5.conf

## JDBC Connection
Required connection properties:

- integratedSecurity=true
- authenticationSchema=JavaKerberos

Only the krb5.conf and login.conf are required for the database connection and not the Java class

## HTTP Connection
To make an HTTP request, you can use the invoke static connector and call the Java class *com.newrez.kerberos.KerberosHttpURLConnection*. The parameters to pass into this request to form the HTTP request are:

- context
- username
- password
- url
- method
- body
- properties
