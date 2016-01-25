package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JMenuItem;

import util.ClipboardUtil;
import websec.Sqlmap;

/**
 * @author wolha
 *
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory {
	/**
	 * burp objects
	 */
	private IExtensionHelpers helpers;

	/**
	 * Extension name
	 */
	private static final String EXTENSION_NAME = "SqlPoC";

	/**
	 * Context menu caption
	 */
	public static String CONTEXT_GENERATE_POC = "Copy sqlmap PoC to Clipboard";

	/**
	 * obtain our output and error streams
	 */
	public static PrintWriter stdout;
	/**
	 * obtain our output and error streams
	 */
	public static PrintWriter stderr;

	//
	// implement IBurpExtender
	//
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// set our extension name
		callbacks.setExtensionName(EXTENSION_NAME);

		// register ourselves as a new context menu factory
		callbacks.registerContextMenuFactory(this);

		// obtain our output and error streams
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stderr = new PrintWriter(callbacks.getStderr(), true);
	}

	//
	// implement IContextMenuFactory
	//
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

		// store argument
		final IContextMenuInvocation in = invocation;
		final IHttpRequestResponse messages[] = in.getSelectedMessages();
		final byte context = in.getInvocationContext();

		// menu item
		List<JMenuItem> menuItems = new LinkedList<JMenuItem>();
		JMenuItem menuItemGeneratePoc = new JMenuItem(CONTEXT_GENERATE_POC);

		// define event handler
		menuItemGeneratePoc.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				// write a message to our output stream
				stdout.println("Selected: " + e.getActionCommand());
				stdout.println("Context: " + context);
				stdout.println("Message count: " + messages.length);

				// if the selected menu is
				if (e.getActionCommand().equals(CONTEXT_GENERATE_POC)) {

					// processing if any messages are selected
					if (messages != null && messages.length > 0) {
						IHttpRequestResponse message = messages[0];

						// execute if any of the below is selected
						// - message editor
						// - message viewer
						// - proxy history
						if (context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
								|| context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
								|| context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
								|| context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE
								|| context == IContextMenuInvocation.CONTEXT_PROXY_HISTORY) {

							IRequestInfo request = helpers.analyzeRequest(message);
							byte[] requestInByteArray = message.getRequest();

							// command object
							Sqlmap sql = new Sqlmap();

							// retrieve URL
							sql.setUrl(request.getUrl().toString());

							// retrieve Host, User-Agent, Referrer, Cookie, and
							// other headers
							for (String header : request.getHeaders()) {
								// ignore a request line
								if (Sqlmap.isRequestLine(header)) {
									continue;
								}
								// ignore Content-Length header (added by
								// sqlmap)
								if (header.startsWith(Sqlmap.HEADER_NAME_CONTENT_LENGTH)) {
									continue;
								}

								if (header.startsWith(Sqlmap.HEADER_NAME_COOKIE)) {
									sql.setCookie(header.substring(Sqlmap.HEADER_NAME_COOKIE.length()));
								} else if (header.startsWith(Sqlmap.HEADER_NAME_HOST)) {
									sql.setHost(header.substring(Sqlmap.HEADER_NAME_HOST.length()));
								} else if (header.startsWith(Sqlmap.HEADER_NAME_REFERRER)) {
									sql.setReferrer(header.substring(Sqlmap.HEADER_NAME_REFERRER.length()));
								} else if (header.startsWith(Sqlmap.HEADER_NAME_USER_AGENT)) {
									sql.setUserAgent(header.substring(Sqlmap.HEADER_NAME_USER_AGENT.length()));
								} else {
									// overwrite headers
									if (sql.getHeaders().isEmpty()) {
										sql.setHeaders(header);
									} else {
										sql.setHeaders(sql.getHeaders() + Sqlmap.HEADER_DELIMITER + header);
									}
								}
							}

							// retrieve POST data
							if (request.getMethod().equals("POST")) {
								sql.setData(new String(Arrays.copyOfRange(requestInByteArray, request.getBodyOffset(),
										requestInByteArray.length)));
							}

							// retrieve selected parameter name
							int[] selectionBounds = in.getSelectionBounds();
							if (selectionBounds != null && selectionBounds.length == 2
									&& selectionBounds[0] < selectionBounds[1]) {
								byte[] selectionBytes = Arrays.copyOfRange(requestInByteArray, selectionBounds[0],
										selectionBounds[1]);
								if (selectionBytes != null && selectionBytes.length > 0) {
									sql.setParameter(new String(selectionBytes));
								}
							}

							// generate sqlmap command and set it to clipboard
							ClipboardUtil.setClipboard(sql.generateCommand());
						} else {
							// if no item is selected, only write log
							stdout.println("no item selected.");
						}
					}
				}
			}
		});

		menuItems.add(menuItemGeneratePoc);

		return (menuItems);
	}
}
