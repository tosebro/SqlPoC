/**
 *  manipulate clipboard
 */
package util;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

/**
 * Class for treating Clipboard.
 * 
 * @author tosebro
 *
 */
public class ClipboardUtil {
	//
	// Copy byte array to clipboard
	//
	public static void setClipboard(byte[] bytes) {
		try {
			setClipboard(new String(bytes, "UTF-8"));
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	//
	// Copy text to clipboard
	//
	public static void setClipboard(String text) {
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringSelection selection = new StringSelection(text);
		clipboard.setContents(selection, selection);
	}

}
