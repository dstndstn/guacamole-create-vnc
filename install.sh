#! /bin/bash

# assume "mvn package" has already been run!

cd $(dirname $0)
pwd

GUACAMOLE_HOME=/cm/shared/apps/guacamole

mkdir -p ${GUACAMOLE_HOME}
mkdir -p ${GUACAMOLE_HOME}/bin
mkdir -p ${GUACAMOLE_HOME}/extensions
mkdir -p ${GUACAMOLE_HOME}/guacamole
mkdir -p ${GUACAMOLE_HOME}/tomcat/ssh-sockets

cat scripts/tomcat-ssh-config | sed s+/etc/guacamole+${GUACAMOLE_HOME}+g > ${GUACAMOLE_HOME}/tomcat/ssh_config
touch ${GUACAMOLE_HOME}/tomcat/ssh-known-hosts

#scp cn001:/cm/shared/guacamole/create-vnc/id_createvnc_computenode ${GUACAMOLE_HOME}/tomcat/

chown -R tomcat ${GUACAMOLE_HOME}/tomcat

# Install updated systemctl service file for tomcat9, setting the GUACAMOLE_HOME environment variable.  This is adapted from the Ubuntu 18.04 tomcat9 service file.
cat scripts/tomcat9.service | sed s+/etc/guacamole+${GUACAMOLE_HOME}+g > /lib/systemd/system/tomcat9.service
systemctl daemon-reload

# Install sudoers file!
#cat scripts/guacamole-sudoers | sed s+/etc/guacamole+${GUACAMOLE_HOME}+g > /etc/sudoers.d/guacamole
# Note that this must also be installed on the target machines that will run the remote desktops

cp target/guacamole-create-vnc-1.5.3.jar ${GUACAMOLE_HOME}/extensions/
service tomcat9 restart

# Local commands
for x in launch-vnc launch-vnc-for list-vnc read-vnc-passwd stop-vnc; do
    cp scripts/$x ${GUACAMOLE_HOME}/bin
done

# Compute node commands
for x in list-vnc run-vnc stop-vnc; do
    cp scripts/$x ${GUACAMOLE_HOME}/bin
done

# Symlinks for Slurm commands
for x in sbatch scancel sinfo; do
    ln -s $(which $x) ${GUACAMOLE_HOME}/bin
done

touch ${GUACAMOLE_HOME}/guacamole.properties

