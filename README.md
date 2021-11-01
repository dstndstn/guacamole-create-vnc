guacamole-create-vnc
====================

This is an extension module for Apache Guacamole that dynamically updates the list of available VNC servers.
It looks for existing VNC servers, and if a newly logged-in user does not already have a server, it creates
one.


Installing
----------

Run
```
mvn package
```
to create the output file ``target/guacamole-create-vnc-1.3.0.jar``.

Copy that file into place, along with support scripts
```
sudo cp target/guacamole-create-vnc-1.3.0.jar /etc/guacamole/extensions
sudo cp scripts/update-vnc-list /etc/guacamole
sudo cp scripts/start-vnc /etc/guacamole
sudo cp scripts/guacamole-sudoers /etc/sudoers.d/guacamole
```

License
-------
Copyright Dustin Lang 2021.  Apache license (see src/licenses/LICENSE)
