package org.eclipse.equinox.storage;

import static org.junit.Assert.*;

import org.eclipse.equinox.internal.security.storage.TestStringVerifier;
import org.eclipse.equinox.security.storage.StorageException;
import org.junit.Test;

public class SecurePreferencesRootTest {
	

	@Test(expected=StorageException.class)
	public void verifyTestString_TestStringNull_ExceptionThrown() throws StorageException {	
		(new TestStringVerifier()).verify((String)null);
	}
	
	@Test(expected=StorageException.class)
	public void verifyTestString_TestStringEmpty_ExceptionThrown() throws StorageException {	
		(new TestStringVerifier()).verify("");
	}
	
	@Test(expected=StorageException.class)
	public void verifyTestString_TestWithoutParts_ExceptionThrown() throws StorageException {	
		(new TestStringVerifier()).verify(" ");
	}
	
	@Test(expected=StorageException.class)
	public void verifyTestString_NonNummericPart_ReturnTrue() throws StorageException {
		(new TestStringVerifier()).verify("abc\t456\t456\t123");
	}
	
	@Test(expected=StorageException.class)
	public void verifyTestString_InvalidFirstPairs_ExceptionThrown() throws StorageException {
		(new TestStringVerifier()).verify("123\t456\t456\t321");
	}
	
	@Test(expected=StorageException.class)
	public void verifyTestString_InvalidSecondPairs_ExceptionThrown() throws StorageException {
		(new TestStringVerifier()).verify("123\t456\t654\t123");
	}
	

	@Test
	public void verifyTestString_MatchingPairs_ReturnTrue() throws StorageException {
		boolean rv = false;
		rv = (new TestStringVerifier()).verify("123\t456\t456\t123");
		
		assertTrue(rv);
	}
	
	@Test
	public void verifyTestString_MatchesVerificationSample_ReturnTrue() throws StorageException {
		
		boolean rv = false;
		
		rv = (new TestStringVerifier()).verify("-> brown fox jumped over lazy dog <-");
	
		assertTrue(rv);
	}
	
}
