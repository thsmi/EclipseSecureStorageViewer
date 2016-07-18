/*******************************************************************************
 * Copyright (c) 2008, 2010 IBM Corporation and others.
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import org.eclipse.equinox.internal.security.auth.nls.SecAuthMessages;
import org.eclipse.equinox.internal.security.storage.friends.*;
import org.eclipse.equinox.security.storage.StorageException;

/**
 * Root secure preference node. In addition to usual things it stores location,
 * modified status, encryption algorithm, and performs save and load.
 */
public class SecurePreferencesRoot extends SecurePreferences implements IStorageConstants {

	private static final String VERSION_KEY = "org.eclipse.equinox.security.preferences.version"; //$NON-NLS-1$
	private static final String VERSION_VALUE = "1"; //$NON-NLS-1$

	/**
	 * The node used by the secure preferences itself
	 */
	private final static String PROVIDER_NODE = "/org.eclipse.equinox.secure.storage"; //$NON-NLS-1$

	/**
	 * Node used to store password verification tokens
	 */
	private final static String PASSWORD_VERIFICATION_NODE = PROVIDER_NODE + "/verification"; //$NON-NLS-1$


	private static final String DIGEST_ALGORITHM = "MD5"; //$NON-NLS-1$

	private String password;

	private JavaEncryption cipher = new JavaEncryption();

	public SecurePreferencesRoot(String password) throws IOException {
		super(null, null);
		this.password = password;
	}

	public JavaEncryption getCipher() {
		return cipher;
	}

	public SecurePreferencesRoot load(String filename) throws StorageException {

		if (filename == null)
			throw new StorageException(StorageException.BAD_STORAGE_FILE, StorageException.badStorageFile);

		Properties properties = new Properties();

		try (InputStream is = new FileInputStream(filename)) {

			properties.load(is);

		} catch (IllegalArgumentException | IOException e) {
			throw new StorageException(StorageException.BAD_STORAGE_FILE, StorageException.badStorageFile);
		}

		// In future new versions could be added
		Object version = properties.get(VERSION_KEY);
		if ((version != null) && !VERSION_VALUE.equals(version))
			throw new StorageException(StorageException.BAD_STORAGE_VERSION, StorageException.badStorageVersion);

		properties.remove(VERSION_KEY);

		// Process encryption algorithms
		if (properties.containsKey(CIPHER_KEY) && properties.containsKey(KEY_FACTORY_KEY)) {
			Object cipherAlgorithm = properties.get(CIPHER_KEY);
			Object keyFactoryAlgorithm = properties.get(KEY_FACTORY_KEY);
			if ((cipherAlgorithm instanceof String) && (keyFactoryAlgorithm instanceof String))
				cipher.setAlgorithms((String) cipherAlgorithm, (String) keyFactoryAlgorithm);
			properties.remove(CIPHER_KEY);
			properties.remove(KEY_FACTORY_KEY);
		}

		for (Object externalKey : properties.keySet()) {

			Object value = properties.get(externalKey);
			if (!(externalKey instanceof String))
				continue;

			if (!(value instanceof String))
				continue;

			PersistedPath storedPath = new PersistedPath((String) externalKey);
			if (storedPath.getKey() == null)
				continue;

			SecurePreferences node = node(storedPath.getPath());
			// don't use regular put() method as that would mark node as dirty
			node.internalPut(storedPath.getKey(), (String) value);
		}

		return this;
	}

	public String getMasterPassword() throws StorageException {

		try {
			MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
			byte[] digested = digest.digest(new String(this.password).getBytes());

			return Base64.encode(digested);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		throw new StorageException(StorageException.NO_PASSWORD, SecAuthMessages.loginNoPassword);
	}

	/**
	 * Provides password for a new entry using: 1) default password, if any 2a)
	 * if options specify usage of specific module, that module is polled to
	 * produce password 2b) otherwise, password provider with highest priority
	 * is used to produce password
	 */
	public String getPassword(String moduleID) throws StorageException {

		if (moduleID == null)
			throw new StorageException(StorageException.NO_SECURE_MODULE, SecAuthMessages.invalidEntryFormat);
		if (DEFAULT_PASSWORD_ID.equals(moduleID))
			throw new StorageException(StorageException.NO_SECURE_MODULE, SecAuthMessages.noDefaultPassword);

		String key = "org.eclipse.equinox.security.ui.defaultpasswordprovider";

		// is there password verification string already?
		SecurePreferences node = node(PASSWORD_VERIFICATION_NODE);

		String passwd = this.getMasterPassword();

		// verify password using sample text
		String encryptedData = node.internalGet(key);
		if (encryptedData == null)
			throw new StorageException(StorageException.NO_PASSWORD, SecAuthMessages.loginNoPassword);
		
		CryptoData data = new CryptoData(encryptedData);
		try {
			byte[] decryptedData = getCipher().decrypt(passwd, data);
			
			if (new TestStringVerifier().verify(decryptedData))
				return passwd;

		} catch (IllegalBlockSizeException e) {
		} catch (BadPaddingException e) {
		}

		throw new StorageException(StorageException.NO_PASSWORD, SecAuthMessages.loginNoPassword);
	}

}
