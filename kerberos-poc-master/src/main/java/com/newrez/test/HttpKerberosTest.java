package com.newrez.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import com.newrez.kerberos.KerberosHttpURLConnection;

public class HttpKerberosTest {

	@SuppressWarnings("serial")
	public static void main(final String[] args) throws Exception {

		if (args.length != 3) {
			System.out.println("USAGE: HttpKerberosTest <username> <password> <domain>");
			return;
		}

		System.setProperty("java.security.auth.login.config", "/Users/alaa.abed/conf/login.conf");
		System.setProperty("java.security.krb5.conf", "/Users/alaa.abed/conf/krb5.conf");
		System.setProperty("sun.security.krb5.debug", "true");

		HttpURLConnection conn = KerberosHttpURLConnection.connect("http-client", args[0] + "@" + args[2], args[1],
				"http://onbasesvcsdev.ad.shellpointmtg.com/v1/keywords/200", "GET", null,
				new HashMap<String, List<String>>() {
					{
						put("Accept", Arrays.asList("application/json"));
						put("x-license-type", Arrays.asList("Concurrent"));
					}
				});

		System.out.println("HTTP Status Code: " + conn.getResponseCode());
		System.out.println("HTTP Status Message: " + conn.getResponseMessage());

		String readLine;
		BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		while (((readLine = reader.readLine()) != null)) {
			System.out.println(readLine);
		}
	}
}