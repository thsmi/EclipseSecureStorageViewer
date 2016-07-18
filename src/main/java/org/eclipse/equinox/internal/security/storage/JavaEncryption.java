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

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.Map.Entry;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.eclipse.equinox.internal.security.auth.nls.SecAuthMessages;
import org.eclipse.equinox.internal.security.storage.friends.*;
import org.eclipse.equinox.security.storage.StorageException;

/**
 * Note that algorithm detection skips aliases:
 *    Alg.Alias.Cipher.ABC
 * only a few aliases are useful and it will be harder to separate human-readable
 * aliases from internal ones.
 *
 */
public class JavaEncryption {

	private final static String SECRET_KEY_FACTORY = "SecretKeyFactory."; //$NON-NLS-1$
	private final static String CIPHER = "Cipher."; //$NON-NLS-1$

	private final static String sampleText = "sample text for roundtrip testing"; //$NON-NLS-1$

	private final static String SAMPLE_PASSWORD = "password1";
	private final static String SAMPLE_MODULE = "abc";

	/**
	 * Default cipher algorithm to use in secure storage
	 */
	public String DEFAULT_CIPHER = "PBEWithMD5AndDES"; //$NON-NLS-1$

	
	static private final int SALT_ITERATIONS = 10;

	private String keyFactoryAlgorithm = null;
	private String cipherAlgorithm = null;

	private boolean initialized = false;

	private HashMap<String,String> availableCiphers;

	public JavaEncryption() {
		// placeholder
	}

	public String getKeyFactoryAlgorithm() {
		return keyFactoryAlgorithm;
	}

	public String getCipherAlgorithm() {
		return cipherAlgorithm;
	}

	public void setAlgorithms(String cipherAlgorithm, String keyFactoryAlgorithm) {
			this.cipherAlgorithm = cipherAlgorithm;
			this.keyFactoryAlgorithm = keyFactoryAlgorithm;
	}

	private void init() throws StorageException {
		
		if (initialized)
			return;
		
		initialized = true;

		if (cipherAlgorithm != null && keyFactoryAlgorithm != null) {
			if (roundtrip(cipherAlgorithm, keyFactoryAlgorithm))
				return;
			// this is a bad situation - JVM cipher no longer available. Both log and throw an exception
			String msg = String.format(SecAuthMessages.noAlgorithm, cipherAlgorithm);
			StorageException e = new StorageException(StorageException.INTERNAL_ERROR, msg);
			System.err.println(msg + e);
			throw e;
		}
		if (cipherAlgorithm == null || keyFactoryAlgorithm == null) {
			cipherAlgorithm = DEFAULT_CIPHER;
			keyFactoryAlgorithm = IStorageConstants.DEFAULT_KEY_FACTORY;			
		}
		if (roundtrip(cipherAlgorithm, keyFactoryAlgorithm))
			return;
		String unavailableCipher = cipherAlgorithm;

		detect();
		if (availableCiphers.size() == 0)
			throw new StorageException(StorageException.INTERNAL_ERROR, SecAuthMessages.noAlgorithms);

		// use first available
		cipherAlgorithm =  availableCiphers.keySet().iterator().next();
		keyFactoryAlgorithm =  availableCiphers.get(cipherAlgorithm);

		String msg = String.format(SecAuthMessages.usingAlgorithm, unavailableCipher, cipherAlgorithm);
		System.err.println(msg);
	}

	public CryptoData encrypt(String moduleId, String password, byte[] clearText) throws StorageException {
		init();
		return internalEncrypt(moduleId, password, clearText);
	}

	private CryptoData internalEncrypt(String moduleId, String password, byte[] clearText) throws StorageException {
		try {
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(keyFactoryAlgorithm);
			SecretKey key = keyFactory.generateSecret(new PBEKeySpec(password.toCharArray()));

			byte[] salt = new byte[8];
			SecureRandom random = new SecureRandom();
			random.nextBytes(salt);
			PBEParameterSpec entropy = new PBEParameterSpec(salt, SALT_ITERATIONS);

			Cipher c = Cipher.getInstance(cipherAlgorithm);
			c.init(Cipher.ENCRYPT_MODE, key, entropy);

			byte[] result = c.doFinal(clearText);
			return new CryptoData(moduleId, salt, result);
		} catch (InvalidKeyException e) {
			handle(e, StorageException.ENCRYPTION_ERROR);
			return null;
		} catch (InvalidAlgorithmParameterException e) {
			handle(e, StorageException.ENCRYPTION_ERROR);
			return null;
		} catch (IllegalBlockSizeException e) {
			handle(e, StorageException.ENCRYPTION_ERROR);
			return null;
		} catch (BadPaddingException e) {
			handle(e, StorageException.ENCRYPTION_ERROR);
			return null;
		} catch (InvalidKeySpecException e) {
			handle(e, StorageException.INTERNAL_ERROR);
			return null;
		} catch (NoSuchPaddingException e) {
			handle(e, StorageException.INTERNAL_ERROR);
			return null;
		} catch (NoSuchAlgorithmException e) {
			handle(e, StorageException.INTERNAL_ERROR);
			return null;
		}
	}

	public byte[] decrypt(String password, CryptoData encryptedData) throws StorageException, IllegalStateException, IllegalBlockSizeException, BadPaddingException {
		init();
		return internalDecrypt(password, encryptedData);
	}

	private byte[] internalDecrypt(String password, CryptoData encryptedData) throws StorageException, IllegalStateException, IllegalBlockSizeException, BadPaddingException {
		try {
			
			
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(keyFactoryAlgorithm);
			SecretKey key = keyFactory.generateSecret(new PBEKeySpec(password.toCharArray()));

			PBEParameterSpec entropy = new PBEParameterSpec(encryptedData.getSalt(), SALT_ITERATIONS);

			Cipher c = Cipher.getInstance(cipherAlgorithm);
			c.init(Cipher.DECRYPT_MODE, key, entropy);

			byte[] result = c.doFinal(encryptedData.getData());
			return result;
		} catch (InvalidAlgorithmParameterException | InvalidKeyException | InvalidKeySpecException | NoSuchPaddingException | NoSuchAlgorithmException e) {
			handle(e, StorageException.INTERNAL_ERROR);
			return null;
		} 
	}

	private void handle(Exception e, int internalCode) throws StorageException {
			e.printStackTrace();
		StorageException exception = new StorageException(internalCode, e);
		throw exception;
	}

	/////////////////////////////////////////////////////////////////////////////////////
	// Algorithm detection

	/**
	 * Result: Map:
	 *    <String>cipher -> <String>keyFactory
	 */
	public HashMap<String,String> detect() {
		Set<String> ciphers = findProviders(CIPHER);
		Set<String> keyFactories = findProviders(SECRET_KEY_FACTORY);
		availableCiphers = new HashMap<>(ciphers.size());

		for (String cipher : ciphers) {
			// check if there is a key factory with the same name
			if (keyFactories.contains(cipher)) {
				if (roundtrip(cipher, cipher)) {
					availableCiphers.put(cipher, cipher);
					continue;
				}
			}
			for (String keyFactory : keyFactories) {
				if (roundtrip(cipher, keyFactory)) {
					availableCiphers.put(cipher, keyFactory);
					continue;
				}
			}
		}
		return availableCiphers;
	}

	private Set<String> findProviders(String prefix) {
		Provider[] providers = Security.getProviders();
		Set<String> algorithms = new HashSet<>();
		int prefixLength = prefix.length();
		
		for (Provider provider : providers) {
			
			for (Entry<Object, Object> entry : provider.entrySet()) {

				Object key = entry.getKey();
				if (key == null)
					continue;
				
				if (!(key instanceof String))
					continue;

				String value = (String) key;
				if (value.indexOf(' ') != -1) // skips properties like "[Cipher.ABC SupportedPaddings]"
					continue;
				
				if (value.startsWith(prefix)) {
					String keyFactory = value.substring(prefixLength);
					algorithms.add(keyFactory);
				}
			}
		}
		return algorithms;
	}

	private boolean roundtrip(String testCipher, String testKeyFactory) {
		boolean storeInitState = initialized;
		String storedCipherAlgorithm = cipherAlgorithm;
		String storedKeyAlgorithm = keyFactoryAlgorithm;
	
		initialized = true;
		
		try {
			cipherAlgorithm = testCipher;
			keyFactoryAlgorithm = testKeyFactory;
			CryptoData encrypted = internalEncrypt(SAMPLE_MODULE, SAMPLE_PASSWORD, StorageUtils.getBytes(sampleText));
			byte[] roundtripBytes = internalDecrypt(SAMPLE_PASSWORD, encrypted);
			String result = StorageUtils.getString(roundtripBytes);
			return sampleText.equals(result);
		} catch (Exception e) {
			// internal implementation throws both checked and unchecked
			// exceptions (without much documentation to go on), so have to use catch-all
			return false;
		} finally { // reset back
			cipherAlgorithm = storedCipherAlgorithm;
			keyFactoryAlgorithm = storedKeyAlgorithm;
			initialized = storeInitState;
		}
	}

}
