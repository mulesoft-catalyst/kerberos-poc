package com.newrez.test;

import java.sql.*;

public class JDBCKerberosTest {

	public static void main(String[] args) {

		if (args.length != 2) {
			System.out.println("USAGE: JDBCKerberosTest <username> <password>");
			return;
		}

		Connection con = null;

        System.setProperty("java.security.auth.login.config", "/Users/alaa.abed/conf/login.conf");
        System.setProperty("java.security.krb5.conf", "/Users/alaa.abed/conf/krb5.conf");
        System.setProperty("sun.security.krb5.debug", "true");

		String connectionUrl = "jdbc:sqlserver://AG_LOS.newpenn.local:14332;databaseName=IT_Operations;integratedSecurity=true;authenticationScheme=JavaKerberos;user=" + args[0] + ";password=" + args[1];

		try {
			Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");

			con = DriverManager.getConnection(connectionUrl);

			DatabaseMetaData dbmd = con.getMetaData();

			System.out.println("dbmd:driver version = " + dbmd.getDriverVersion());
			System.out.println("dbmd:driver name = " + dbmd.getDriverName());
			System.out.println("db name = " + dbmd.getDatabaseProductName());
			System.out.println("db ver = " + dbmd.getDatabaseProductVersion());

		}

		catch (Exception e) {
			e.printStackTrace();
		}
	}
}