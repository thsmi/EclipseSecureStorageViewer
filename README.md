# EclipseSecureStorageViewer

Eclipse offers a secure storage for securely saving passwords protected by a master password. 

But there is no UI to retrieve/lookup saved passwords. 

This java application wraps the original code to lookup, decrypt and prints stored passwords. It lists all entries of the secure storage container. 

Please keep in mind, you need to know the master password, and only linux secure storage containers are supported.


When starting the application you need to specify two parameters. The first parameter is the path to the secure storage file. It is typically name secure_storage and located somehere in your home directory. The second argument is your master password.

The output looks like illustrated below

    Entries stored in D:\Projects\EclipseSecureStorage\secure_storage

    Container com.ibm.team.auth.info
        Entry.......: user@https://rtc.example.com:9443/ccm/
        Value.......: vaKe9wuocohcoimeeghu
        Encrypted...: true

        Entry.......: de\user@https://rtc.example.com:9443/ccm/
        Value.......: choGh4wooneegienguwu
        Encrypted...: true
    
        Entry.......: user@https://rtc.example.com:9443/jts/
        Value.......: ohtoh1Queingaweihere
        Encrypted...: true

    Container org.eclipse.equinox.secure.storage
      Container verification
          Entry.......: org.eclipse.equinox.security.ui.defaultpasswordprovider
          Value.......: 6570	119	119	6570
          Encrypted...: true