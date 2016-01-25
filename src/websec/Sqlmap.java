/**
 * 
 */
package websec;

import java.util.regex.Pattern;

/**
 * Class for treating sqlmap command.
 * 
 * @author tosebro
 */
public class Sqlmap {

	/**
	 * sqlmap path in Kali Linux
	 */
	public static final String DEFAULT_SQLMAP_PATH = "sqlmap.py";

	/**
	 * field-name for Cookie header
	 */
	public static final String HEADER_NAME_COOKIE = "Cookie: ";
	/**
	 * field-name for Host header
	 */
	public static final String HEADER_NAME_HOST = "Host: ";
	/**
	 * field-name for User-Agent header
	 */
	public static final String HEADER_NAME_USER_AGENT = "User-Agent: ";
	/**
	 * field-name for Referrer header
	 */
	public static final String HEADER_NAME_REFERRER = "Referer: ";
	/**
	 * field-name for Content-Length header
	 */
	public static final String HEADER_NAME_CONTENT_LENGTH = "Content-Length: ";
	/**
	 * delimiter for http headers
	 */
	public static final String HEADER_DELIMITER = "\\r\\n";

	/**
	 * path of sqlmap
	 */
	private String path = DEFAULT_SQLMAP_PATH;
	/**
	 * target URL
	 */
	private String url = "";
	/**
	 * POST data (if any)
	 */
	private String data = "";
	/**
	 * Cookie (field-value only)
	 */
	private String cookie = "";
	/**
	 * Referrer (field-value only)
	 */
	private String referrer = "";
	/**
	 * General http headers. Specify whole header-field, and headers delimited
	 * by CRLF (\r\n)
	 */
	private String headers = "";
	/**
	 * Host header (field-value only)
	 */
	private String host = "";
	/**
	 * User-Agent header (field-value only)
	 */
	private String userAgent = "";
	/**
	 * target parameter name (if any)
	 */
	private String parameter = "";

	/**
	 * default constructor
	 */
	public Sqlmap() {
	}

	/**
	 * @return sqlmap command
	 */
	public String generateCommand() {
		// sqlmap command
		StringBuffer sb = new StringBuffer();
		// create common part
		sb.append(String.format(
				"python %s -u \"%s\" --cookie=\"%s\" --referer=\"%s\" --headers=\"%s\" --host=\"%s\" --user-agent=\"%s\" --all",
				path, url, cookie, referrer, headers, host, userAgent));
		// append POST data
		if (!data.isEmpty()) {
			sb.append(String.format(" --data=\"%s\"", data));
		}
		// specify parameter name
		if (!parameter.isEmpty()) {
			sb.append(String.format(" -p %s", parameter));
		}

		return sb.toString();
	}

	/**
	 * @return the path
	 */
	public String getPath() {
		return path;
	}

	/**
	 * @param path
	 *            the path to set
	 */
	public void setPath(String path) {
		this.path = path;
	}

	/**
	 * @return the url
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * @param url
	 *            the url to set
	 */
	public void setUrl(String url) {
		this.url = url;
	}

	/**
	 * @return the data
	 */
	public String getData() {
		return data;
	}

	/**
	 * @param data
	 *            the data to set
	 */
	public void setData(String data) {
		this.data = data;
	}

	/**
	 * @return the cookie
	 */
	public String getCookie() {
		return cookie;
	}

	/**
	 * @param cookie
	 *            the cookie to set
	 */
	public void setCookie(String cookie) {
		this.cookie = cookie;
	}

	/**
	 * @return the referrer
	 */
	public String getReferrer() {
		return referrer;
	}

	/**
	 * @param referrer
	 *            the referrer to set
	 */
	public void setReferrer(String referrer) {
		this.referrer = referrer;
	}

	/**
	 * @return the headers
	 */
	public String getHeaders() {
		return headers;
	}

	/**
	 * @param headers
	 *            the headers to set
	 */
	public void setHeaders(String headers) {
		this.headers = headers;
	}

	/**
	 * @return the host
	 */
	public String getHost() {
		return host;
	}

	/**
	 * @param host
	 *            the host to set
	 */
	public void setHost(String host) {
		this.host = host;
	}

	/**
	 * @return the userAgent
	 */
	public String getUserAgent() {
		return userAgent;
	}

	/**
	 * @param userAgent
	 *            the userAgent to set
	 */
	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}

	/**
	 * @return the parameter
	 */
	public String getParameter() {
		return parameter;
	}

	/**
	 * @param parameter
	 *            the parameter to set
	 */
	public void setParameter(String parameter) {
		this.parameter = parameter;
	}

	/**
	 * regex pattern for a request line. the pattern gadards the target text as
	 * a request line if it starts with upper alphabets sequeence and then
	 * space.
	 */
	private static String REQUEST_LINE_PATTERN = "^[A-Z]+ .+";

	/**
	 * check if the target text is a request line.
	 * 
	 * @param line
	 *            taget text
	 * @return true if if the target text is a request line.
	 */
	public static boolean isRequestLine(String line) {
		if (line == null || line.isEmpty()) {
			return false;
		}

		return Pattern.matches(REQUEST_LINE_PATTERN, line);
	}
}
