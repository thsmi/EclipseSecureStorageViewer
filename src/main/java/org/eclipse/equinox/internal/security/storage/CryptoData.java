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

import org.eclipse.equinox.internal.security.auth.nls.SecAuthMessages;
import org.eclipse.equinox.security.storage.StorageException;

public class CryptoData {

	static final private char MODULE_ID_SEPARATOR = '\t'; // must not be a valid
															// Base64 char

	/**
	 * Separates salt from the data; this must not be a valid Base64 character.
	 */
	static private final char SALT_SEPARATOR = ',';

	final private String moduleID;
	final private byte[] salt;
	final private byte[] encryptedData;

	public CryptoData(String moduleID, byte[] salt, byte[] data) {
		this.moduleID = moduleID;
		this.salt = salt;
		this.encryptedData = data;
	}

	public CryptoData(String data) throws StorageException {
		// separate moduleID
		int pos = data.indexOf(MODULE_ID_SEPARATOR);
		String encrypted;
		if (pos == -1) { // invalid data format
			throw new StorageException(StorageException.DECRYPTION_ERROR, SecAuthMessages.invalidEntryFormat);
		}
		
		if (pos == 0) {
			moduleID = null;
			encrypted = data.substring(1);
		} else {
			moduleID = data.substring(0, pos);
			encrypted = data.substring(pos + 1);
		}

		// separate salt and data
		int saltPos = encrypted.indexOf(SALT_SEPARATOR);

		if (saltPos == -1) {
			// double check that this is not a broken entry
			if (encrypted.length() != 0)
				throw new StorageException(StorageException.DECRYPTION_ERROR, SecAuthMessages.invalidEntryFormat);

			salt = null;
			encryptedData = null;
			return;

		}

		salt = Base64.decode(encrypted.substring(0, saltPos));
		encryptedData = Base64.decode(encrypted.substring(saltPos + 1));
		return;
	}

	public String getModuleID() {
		return moduleID;
	}

	public byte[] getSalt() {
		return salt;
	}

	public byte[] getData() {
		return encryptedData;
	}

}
