/*******************************************************************************
 * Copyright (c) 2007, 2008 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package org.eclipse.equinox.internal.security.storage;

import java.io.*;
import org.eclipse.equinox.internal.security.auth.nls.SecAuthMessages;

/**
 * PLEASE READ BEFORE CHANGING THIS FILE
 * 
 * At present most of the methods expect only file URLs. The API methods
 * take URLs for possible future expansion, and there is some code below
 * that would work with some other URL types, but the only supported URL
 * types at this time are file URLs. Also note that URL paths should not
 * be encoded (spaces should be spaces, not "%x20"). 
 *  
 * On encoding: Java documentation recommends using File.toURI().toURL().
 * However, in this process non-alphanumeric characters (including spaces)
 * get encoded and can not be used with the rest of Eclipse methods that
 * expect non-encoded strings.
 */
public class StorageUtils {

	/**
	 * Characters encoding used by the secure storage.
	 */
	final public static String CHAR_ENCODING = "UTF-8"; //$NON-NLS-1$


	/**
	 * The {@link String#getBytes()} truncates non-ASCII chars. As a result 
	 * new String(string.getBytes()) is not the same as the original string. Moreover,
	 * the default Java encoding can be changed via system variables or startup conditions.
	 */
	static public byte[] getBytes(String string) {
		if (string == null)
			return null;
		try {
			return string.getBytes(CHAR_ENCODING);
		} catch (UnsupportedEncodingException e) {
				String msg = String.format(SecAuthMessages.unsupoprtedCharEncoding, StorageUtils.CHAR_ENCODING);
				System.err.println(msg);
			return string.getBytes();
		}
	}

	/**
	 * The new String(byte[]) method uses default system encoding which
	 * might not properly process non-ASCII characters. 
	 * 
	 * Pairing {@link #getBytes(String)} and {@link #getString(byte[])} methods allows round trip 
	 * of non-ASCII characters. 
	 */
	static public String getString(byte[] bytes) {
		if (bytes == null)
			return null;
		try {
			return new String(bytes, CHAR_ENCODING);
		} catch (UnsupportedEncodingException e) {
				String msg = String.format(SecAuthMessages.unsupoprtedCharEncoding, StorageUtils.CHAR_ENCODING);
				System.err.println(msg);
			return new String(bytes);
		}
	}

}
