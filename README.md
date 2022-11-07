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
to create the output file ``target/guacamole-create-vnc-1.4.0.jar``.

Copy that file into place:
```
sudo cp target/guacamole-create-vnc-1.4.0.jar /etc/guacamole/extensions
```

A number of other files must be copied into place as well; see the
file `install.sh` for details about how we have it installed at
Perimeter Institute.

License
-------
Copyright Dustin Lang 2021.  Apache license (see src/licenses/LICENSE)
