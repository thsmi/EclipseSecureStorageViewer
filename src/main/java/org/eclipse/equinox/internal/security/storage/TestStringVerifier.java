package org.eclipse.equinox.internal.security.storage;

import org.eclipse.equinox.security.storage.StorageException;

public class TestStringVerifier {
	
	/**
	 * Text used to verify password
	 */
	private final static String PASSWORD_VERIFICATION_SAMPLE = "-> brown fox jumped over lazy dog <-"; //$NON-NLS-1$
	

	protected boolean verify(String partA, String partB) {
		try {
			long numA =  Long.decode(partA).longValue();
			long numB = Long.decode(partB).longValue();
			
			if (numA != numB)
				return false;
			
		}catch (NumberFormatException | NullPointerException e) {
			return false;
		}

		
		return true;
	}

	
	/**
	 * Checks if the string is the hard-coded original password verification
	 * sample or a string generated according to the rules in
	 * {@link #createTestString()}.
	 * @throws StorageException 
	 */
	public boolean verify(String test) throws StorageException {
		if (test == null || test.length() == 0)
			throw new StorageException(0, Messages.getString("TestStringVerifier.InvalidString")); //$NON-NLS-1$
		// backward compatibility: check if it is the original hard-coded string
		if (PASSWORD_VERIFICATION_SAMPLE.equals(test))
			return true;
		
		String[] parts = test.split("\t"); //$NON-NLS-1$
		
		if (parts.length != 4)
			throw new StorageException(0, Messages.getString("TestStringVerifier.InvalidTokens")+parts.length); //$NON-NLS-1$
		
		if (!this.verify(parts[0] , parts[3]))
			throw new StorageException(0, Messages.getString("TestStringVerifier.Token0DoesNotMatchToken3")); //$NON-NLS-1$
		
		if (!this.verify(parts[1], parts[2]))
			throw new StorageException(0, Messages.getString("TestStringVerifier.Token1DoesNotMatchToken2")); //$NON-NLS-1$

		return true;
	}
	
	public boolean verify(byte[] data) throws StorageException {
		return this.verify(StorageUtils.getString(data));
	}
}
