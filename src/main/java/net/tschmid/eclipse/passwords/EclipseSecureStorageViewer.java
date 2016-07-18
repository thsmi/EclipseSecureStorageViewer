package net.tschmid.eclipse.passwords;

import java.io.IOException;

import org.eclipse.equinox.internal.security.storage.SecurePreferencesRoot;
import org.eclipse.equinox.security.storage.ISecurePreferences;
import org.eclipse.equinox.security.storage.StorageException;

public class EclipseSecureStorageViewer {

	private static void listEntries(ISecurePreferences pref, String prefix) throws StorageException {

		for (String key : pref.keys()) {
			try {
				System.out.println(prefix + "Entry.......: " + key);
				System.out.println(prefix + "Value.......: " + pref.get(key));
				System.out.println(prefix + "Encrypted...: " + pref.isEncrypted(key));
				System.out.println();
			} catch (StorageException e) {
				System.out.println(prefix + "  Failed" + e.getMessage());
			}
		}
	}

	private static void listChildren(ISecurePreferences parent, String prefix) throws StorageException {

		if (parent.keys().length > 0)
			listEntries(parent, prefix + "  ");

		for (String child : parent.childrenNames()) {
			System.out.println(prefix + "Container " + child);
			listChildren(parent.node(child), prefix + "  ");
		}
	}

	public static void main(String[] args) {
		
		if (args.length == 0) {
			System.out.println(" You need to specify the path to the secure container as parameter\n");
			return;
		}
		
		try {

			String filename = args[0];

			System.out.println("Entries stored in " + filename + "\n");

			ISecurePreferences root = (new SecurePreferencesRoot("jambit")).load(filename);

			listChildren(root, "");

		} catch (IOException | StorageException e) {
			e.printStackTrace();
		}
	}

}
