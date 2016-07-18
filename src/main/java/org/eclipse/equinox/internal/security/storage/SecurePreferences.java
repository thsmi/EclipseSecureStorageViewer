/*******************************************************************************
 * Copyright (c) 2008 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package org.eclipse.equinox.internal.security.storage;

import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import org.eclipse.equinox.internal.security.auth.nls.SecAuthMessages;
import org.eclipse.equinox.security.storage.ISecurePreferences;
import org.eclipse.equinox.security.storage.StorageException;

public class SecurePreferences implements ISecurePreferences {

	/**
	 * Pseudo-module ID to use when encryption is done with the default
	 * password.
	 */
	protected final static String DEFAULT_PASSWORD_ID = "org.eclipse.equinox.security.noModule"; //$NON-NLS-1$

	private static final String PATH_SEPARATOR = String.valueOf('/');

	private static final String[] EMPTY_STRING_ARRAY = new String[0];

	/**
	 * Parent node; null if this is a root node
	 */
	final protected SecurePreferences parent;

	/**
	 * Name of this node
	 */
	final private String name;

	/**
	 * Child nodes; created lazily; might be null
	 */
	protected Map<String, SecurePreferences> children;

	/**
	 * Values associated with this node; created lazily; might be null
	 */
	private Map<String, String> values = new HashMap<>();

	public SecurePreferences(SecurePreferences parent, String name) {
		this.parent = parent;
		this.name = name;
	}

	//////////////////////////////////////////////////////////////////////////////////////////
	// Navigation

	@Override
	public SecurePreferences parent() {

		return parent;
	}

	@Override
	public String name() {

		return name;
	}

	@Override
	public String absolutePath() {

		if (parent == null)
			return PATH_SEPARATOR;
		String parentPath = parent.absolutePath();
		if (PATH_SEPARATOR.equals(parentPath)) // parent is the root node?
			return parentPath + name;
		return parentPath + PATH_SEPARATOR + name;
	}

	@Override
	public SecurePreferences node(String pathName) {

		validatePath(pathName);
		return navigateToNode(pathName, true);
	}

	@Override
	public boolean nodeExists(String pathName) {
		validatePath(pathName);
		return (navigateToNode(pathName, false) != null);
	}

	@Override
	public String[] keys() {

		Set<String> keys = values.keySet();
		int size = keys.size();
		String[] result = new String[size];
		int pos = 0;
		for (String key : keys) {
			result[pos++] = key;
		}
		return result;
	}

	@Override
	public String[] childrenNames() {

		if (children == null)
			return EMPTY_STRING_ARRAY;
		Set<String> keys = children.keySet();
		int size = keys.size();
		String[] result = new String[size];
		int pos = 0;
		for (String key : keys) {
			result[pos++] = key;
		}
		return result;
	}

	protected SecurePreferencesRoot getRoot() {
		SecurePreferences result = this;
		while (result.parent() != null)
			result = result.parent();
		return (SecurePreferencesRoot) result;
	}

	protected SecurePreferences navigateToNode(String pathName, boolean create) {
		if (pathName == null || pathName.length() == 0)
			return this;
		int pos = pathName.indexOf('/');
		if (pos == -1)
			return getChild(pathName, create);

		if (pos == 0) // if path requested is absolute, pass it to the root
						// without "/"
			return getRoot().navigateToNode(pathName.substring(1), create);
		// if path requested contains segments, isolate top segment and rest
		String topSegment = pathName.substring(0, pos);
		String otherSegments = pathName.substring(pos + 1);
		SecurePreferences child = getChild(topSegment, create);
		if (child == null && !create)
			return null;
		
		return child.navigateToNode(otherSegments, create);

	}

	synchronized private SecurePreferences getChild(String segment, boolean create) {
		if (children == null) {
			if (!create)
				return null;

			children = new HashMap<>(5);
		}
		SecurePreferences child = children.get(segment);
		if (!create || (child != null))
			return child;
		child = new SecurePreferences(this, segment);
		children.put(segment, child);
		return child;
	}

	//////////////////////////////////////////////////////////////////////////////////////////
	// Load and save

	@Override
	public String get(String key) throws StorageException {

		if (!hasKey(key))
			return null;

		String encryptedValue = internalGet(key);
		if (encryptedValue == null)
			return null;

		CryptoData data = new CryptoData(encryptedValue);
		String moduleID = data.getModuleID();
		if (moduleID == null) { // clear-text value, not encrypted
			if (data.getData() == null)
				return null;
			return StorageUtils.getString(data.getData());
		}

		String password = getRoot().getPassword(moduleID);

		try {
			byte[] clearText = getRoot().getCipher().decrypt(password, data);
			return StorageUtils.getString(clearText);
		} catch (IllegalBlockSizeException e) { // invalid password?
			throw new StorageException(StorageException.DECRYPTION_ERROR, e);
		} catch (BadPaddingException e) { // invalid password?
			throw new StorageException(StorageException.DECRYPTION_ERROR, e);
		}
	}

	/**
	 * For internal use - retrieve moduleID used to encrypt this value
	 */
	public String getModule(String key) {
		if (!hasKey(key))
			return null;
		String encryptedValue = internalGet(key);
		if (encryptedValue == null)
			return null;
		try {
			CryptoData data = new CryptoData(encryptedValue);
			String moduleID = data.getModuleID();
			if (DEFAULT_PASSWORD_ID.equals(moduleID))
				return null;
			return moduleID;
		} catch (StorageException e) {
			return null;
		}
	}

	synchronized protected void internalPut(String key, String value) {
		values.put(key, value);
	}

	protected String internalGet(String key) {
		return values.get(key);
	}

	private void validatePath(String path) {
		if (isValid(path))
			return;
		String msg = String.format(SecAuthMessages.invalidNodePath, path);
		throw new IllegalArgumentException(msg);
	}

	/**
	 * In additions to standard Preferences descriptions of paths, the following
	 * conditions apply: Path can contains ASCII characters between 32 and 126
	 * (alphanumerics and printable characters). Path can not contain two or
	 * more consecutive forward slashes ('/'). Path can not end with a trailing
	 * forward slash.
	 */
	private boolean isValid(String path) {
		if (path == null || path.length() == 0)
			return true;
		char[] chars = path.toCharArray();
		boolean lastSlash = false;
		for (int i = 0; i < chars.length; i++) {
			if ((chars[i] <= 31) || (chars[i] >= 127))
				return false;
			boolean isSlash = (chars[i] == '/');
			if (lastSlash && isSlash)
				return false;
			lastSlash = isSlash;
		}
		return (chars.length > 1) ? (chars[chars.length - 1] != '/') : true;
	}

	protected boolean hasKey(String key) {
		return values.containsKey(key);
	}

	@Override
	public boolean isEncrypted(String key) throws StorageException {

		if (!hasKey(key))
			return false;

		String encryptedValue = internalGet(key);
		if (encryptedValue == null)
			return false;

		CryptoData data = new CryptoData(encryptedValue);
		String moduleID = data.getModuleID();
		return (moduleID != null);
	}

}
