package com.newrez.kerberos;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Base64;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class KerberosHttpURLConnection {

	private static final Logger LOGGER = Logger.getLogger(KerberosHttpURLConnection.class.getName());

	public static final String AUTHZ_HEADER = "Authorization";
	public static final String AUTHN_HEADER = "WWW-Authenticate";

	private static final Lock LOCK = new ReentrantLock();

	private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

	private boolean connected = false;

	private String requestMethod = "GET";

	private final Map<String, List<String>> requestProperties = new LinkedHashMap<String, List<String>>();

	private LoginContext loginContext;

	private GSSCredential credential;

	private boolean cntxtEstablished = false;

	private HttpURLConnection conn = null;

	private boolean reqCredDeleg = false;

	private boolean autoDisposeCreds = true;

	public KerberosHttpURLConnection(final String loginModuleName) throws LoginException {
		this.loginContext = new LoginContext(loginModuleName);
		this.loginContext.login();
		this.credential = null;
	}

	public KerberosHttpURLConnection(final GSSCredential creds) {
		this(creds, true);
	}

	public KerberosHttpURLConnection(final GSSCredential creds, final boolean dispose) {
		this.loginContext = null;
		this.credential = creds;
		this.autoDisposeCreds = dispose;
	}

	public KerberosHttpURLConnection(final String loginModuleName, final String username, final String password)
			throws LoginException {
		this.loginContext = new LoginContext(loginModuleName,
				KerberosUtils.getUsernamePasswordHandler(username, password));
		this.loginContext.login();
		this.credential = null;
	}

	private void assertConnected() {
		if (!this.connected) {
			throw new IllegalStateException("Not connected.");
		}
	}

	private void assertNotConnected() {
		if (this.connected) {
			throw new IllegalStateException("Already connected.");
		}
	}

	public static HttpURLConnection connect(final String loginModuleName, final String url, final String method,
			final String body, Map<String, List<String>> properties)
			throws LoginException, GSSException, PrivilegedActionException, IOException {
		return connect(loginModuleName, null, null, url, method, body, properties);
	}
	
	public static HttpURLConnection connect(final String context, final String username, final String password, final String url, final String method,
			final String body, Map<String, List<String>> properties)
			throws LoginException, GSSException, PrivilegedActionException, IOException {

		ByteArrayOutputStream dooutput = null;
		KerberosHttpURLConnection conn = null;

		if (username == null) {
			conn = new KerberosHttpURLConnection(context);
		} else {
			conn = new KerberosHttpURLConnection(context, username, password);
		}
		conn.setRequestMethod(method);
		conn.setRequestProperties(properties);

		if (body != null && body.length() > 0) {
			dooutput = new ByteArrayOutputStream();
			dooutput.write(body.getBytes());
		}

		return conn.connect(new URL(url), dooutput);
	}

	public HttpURLConnection connect(final URL url) throws GSSException, PrivilegedActionException, IOException {
		return this.connect(url, null);
	}

	public HttpURLConnection connect(final URL url, final ByteArrayOutputStream dooutput)
			throws GSSException, PrivilegedActionException, IOException {

		assertNotConnected();

		GSSContext context = null;

		try {
			byte[] data = null;

			KerberosHttpURLConnection.LOCK.lock();
			try {
				// work-around to GSSContext/AD timestamp vs sequence field replay bug
				try {
					Thread.sleep(31);
				} catch (InterruptedException e) {
					assert true;
				}

				context = this.getGSSContext(url);
				context.requestMutualAuth(true);
				context.requestConf(true);
				context.requestInteg(true);
				context.requestReplayDet(true);
				context.requestSequenceDet(true);
				context.requestCredDeleg(this.reqCredDeleg);

				data = context.initSecContext(EMPTY_BYTE_ARRAY, 0, 0);
			} finally {
				KerberosHttpURLConnection.LOCK.unlock();
			}

			this.conn = (HttpURLConnection) url.openConnection();
			this.connected = true;

			for (String key : requestProperties.keySet()) {
				for (String value : this.requestProperties.get(key)) {
					this.conn.addRequestProperty(key, value);
				}
			}

			this.conn.setInstanceFollowRedirects(false);
			this.conn.setRequestMethod(this.requestMethod);

			this.conn.setRequestProperty(AUTHZ_HEADER,
					AuthScheme.NEGOTIATE_HEADER + ' ' + new String(Base64.getEncoder().encode(data)));

			if (null != dooutput && dooutput.size() > 0) {
				this.conn.setDoOutput(true);
				dooutput.writeTo(this.conn.getOutputStream());
			}

			this.conn.connect();

			AuthScheme scheme = AuthScheme.getAuthScheme(this.conn.getHeaderField(AUTHN_HEADER));

			// app servers will not return a WWW-Authenticate on 302, (and 30x...?)
			if (null == scheme) {
				LOGGER.fine("getAuthScheme(...) returned null.");
			} else {
				data = scheme.getToken();

				if (AuthScheme.NEGOTIATE_HEADER.equalsIgnoreCase(scheme.getScheme())) {
					KerberosHttpURLConnection.LOCK.lock();
					try {
						data = context.initSecContext(data, 0, data.length);
					} finally {
						KerberosHttpURLConnection.LOCK.unlock();
					}

					if (null != data) {
						LOGGER.warning("Server requested context loop: " + data.length);
					}

				} else {
					throw new UnsupportedOperationException("Scheme NOT Supported: " + scheme.getScheme());
				}

				this.cntxtEstablished = context.isEstablished();
			}
		} finally {
			this.dispose(context);
		}

		return this.conn;
	}

	private void dispose(final GSSContext context) {
		if (null != context) {
			try {
				KerberosHttpURLConnection.LOCK.lock();
				try {
					context.dispose();
				} finally {
					KerberosHttpURLConnection.LOCK.unlock();
				}
			} catch (GSSException gsse) {
				LOGGER.log(Level.WARNING, "call to dispose context failed.", gsse);
			}
		}

		if (null != this.credential && this.autoDisposeCreds) {
			try {
				this.credential.dispose();
			} catch (GSSException gsse) {
				LOGGER.log(Level.WARNING, "call to dispose credential failed.", gsse);
			}
		}

		if (null != this.loginContext) {
			try {
				this.loginContext.logout();
			} catch (LoginException le) {
				LOGGER.log(Level.WARNING, "call to logout context failed.", le);
			}
		}
	}

	public void disconnect() {
		this.dispose(null);
		this.requestProperties.clear();
		this.connected = false;
		if (null != this.conn) {
			this.conn.disconnect();
		}
	}

	public boolean isContextEstablished() {
		return this.cntxtEstablished;
	}

	private void assertKeyValue(final String key, final String value) {
		if (null == key || key.isEmpty()) {
			throw new IllegalArgumentException("key parameter is null or empty");
		}
		if (null == value) {
			throw new IllegalArgumentException("value parameter is null");
		}
	}

	public void addRequestProperty(final String key, final String value) {
		assertNotConnected();
		assertKeyValue(key, value);

		if (this.requestProperties.containsKey(key)) {
			List<String> val = this.requestProperties.get(key);
			val.add(value);
			this.requestProperties.put(key, val);
		} else {
			setRequestProperty(key, value);
		}
	}

	public void setRequestProperty(final String key, final String value) {
		assertNotConnected();
		assertKeyValue(key, value);

		this.requestProperties.put(key, Arrays.asList(value));
	}

	public void setRequestProperties(final Map<String, List<String>> properties) {
		assertNotConnected();

		if (properties == null) {
			throw new IllegalArgumentException("parameter is null");
		}

		this.requestProperties.clear();
		this.requestProperties.putAll(properties);
	}

	private GSSContext getGSSContext(final URL url) throws GSSException, PrivilegedActionException {

		if (null == this.credential) {
			if (null == this.loginContext) {
				throw new IllegalStateException("GSSCredential AND LoginContext NOT initialized");

			} else {
				this.credential = KerberosUtils.getClientCredential(this.loginContext.getSubject());
			}
		}

		return KerberosUtils.getGSSContext(this.credential, url);
	}

	public InputStream getErrorStream() throws IOException {
		assertConnected();
		return this.conn.getInputStream();
	}

	public String getHeaderField(final int index) {
		assertConnected();
		return this.conn.getHeaderField(index);
	}

	public String getHeaderField(final String name) {
		assertConnected();
		return this.conn.getHeaderField(name);
	}

	public String getHeaderFieldKey(final int index) {
		assertConnected();
		return this.conn.getHeaderFieldKey(index);
	}

	public InputStream getInputStream() throws IOException {
		assertConnected();
		return this.conn.getInputStream();
	}

	public OutputStream getOutputStream() throws IOException {
		assertConnected();
		return this.conn.getOutputStream();
	}

	public int getResponseCode() throws IOException {
		assertConnected();
		return this.conn.getResponseCode();
	}

	public String getResponseMessage() throws IOException {
		assertConnected();
		return this.conn.getResponseMessage();
	}

	public void requestCredDeleg(final boolean requestDelegation) {
		this.assertNotConnected();
		this.reqCredDeleg = requestDelegation;
	}

	public void setRequestMethod(final String method) {
		assertNotConnected();
		this.requestMethod = method;
	}

	static class AuthScheme {

		public static final String BASIC_HEADER = "Basic";
		public static final String NEGOTIATE_HEADER = "Negotiate";
		static final String NTLM_PROLOG = "TlRMTVNT";

		private String scheme;

		private String token;

		public static AuthScheme getAuthScheme(final String header) {

			if (null == header || header.isEmpty()) {
				LOGGER.finer("authorization header was missing/null");
				return null;

			} else if (header.startsWith(NEGOTIATE_HEADER)) {
				return new AuthScheme(NEGOTIATE_HEADER, header.substring(NEGOTIATE_HEADER.length() + 1));

			} else if (header.startsWith(BASIC_HEADER)) {
				return new AuthScheme(BASIC_HEADER, header.substring(BASIC_HEADER.length() + 1));

			} else {
				throw new UnsupportedOperationException("Negotiate or Basic Only:" + header);
			}
		}

		public AuthScheme(final String authScheme, final String authToken) {
			this.scheme = authScheme;
			this.token = authToken;
		}

		boolean isBasicScheme() {
			return BASIC_HEADER.equalsIgnoreCase(scheme);
		}

		boolean isNegotiateScheme() {
			return NEGOTIATE_HEADER.equalsIgnoreCase(scheme);
		}

		boolean isNtlmToken() {
			if (null == token || token.isEmpty()) {
				return false;
			} else {
				return token.startsWith(NTLM_PROLOG);
			}
		}

		public String getScheme() {
			return this.scheme;
		}

		public byte[] getToken() {
			return (null == this.token) ? EMPTY_BYTE_ARRAY : Base64.getDecoder().decode(this.token);
		}
	}

	static class KerberosUtils {

		static final GSSManager MANAGER = GSSManager.getInstance(); // NOPMD

		static final Oid OID = getOid(); // NOPMD

		private KerberosUtils() {
		}

		public static GSSCredential getClientCredential(final Subject subject) throws PrivilegedActionException {

			PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
				public GSSCredential run() throws GSSException {
					return MANAGER.createCredential(null, GSSCredential.DEFAULT_LIFETIME, OID,
							GSSCredential.INITIATE_ONLY);
				}
			};

			return Subject.doAs(subject, action);
		}

		public static GSSContext getGSSContext(final GSSCredential creds, final URL url) throws GSSException {

			return MANAGER.createContext(getServerName(url), OID, creds, GSSContext.DEFAULT_LIFETIME);
		}

		private static Oid getOid() {
			Oid oid = null;
			try {
				oid = new Oid("1.3.6.1.5.5.2");
			} catch (GSSException gsse) {
				LOGGER.log(Level.SEVERE, "Unable to create OID 1.3.6.1.5.5.2 !", gsse);
			}
			return oid;
		}

		static GSSName getServerName(final URL url) throws GSSException {
			return MANAGER.createName("HTTP@" + url.getHost(), GSSName.NT_HOSTBASED_SERVICE, OID);
		}

		public static CallbackHandler getUsernamePasswordHandler(final String username, final String password) {

			LOGGER.fine("username=" + username + "; password=" + password.hashCode());

			CallbackHandler handler = new CallbackHandler() {
				public void handle(final Callback[] callback) {
					for (int i = 0; i < callback.length; i++) {
						if (callback[i] instanceof NameCallback) {
							((NameCallback) callback[i]).setName(username);
						} else if (callback[i] instanceof PasswordCallback) {
							((PasswordCallback) callback[i]).setPassword(password.toCharArray());
						} else {
							LOGGER.warning(
									"Unsupported Callback i=" + i + "; class=" + callback[i].getClass().getName());
						}
					}
				}
			};

			return handler;
		}
	}
}