#! /bin/bash

# assume "mvn package" has already been run!


cd $(dirname $0)
pwd

GUACAMOLE_HOME=/cm/shared/guacamole

mkdir -p ${GUACAMOLE_HOME}
mkdir -p ${GUACAMOLE_HOME}/extensions/

mkdir -p ${GUACAMOLE_HOME}/tomcat/ssh-sockets/
mkdir -p ${GUACAMOLE_HOME}/create-vnc

cat scripts/tomcat-ssh-config | sed s+/etc/guacamole+${GUACAMOLE_HOME}+g > ${GUACAMOLE_HOME}/tomcat/ssh_config
touch ${GUACAMOLE_HOME}/tomcat/ssh-known-hosts
# HACK
#scp cn001:/cm/shared/guacamole/create-vnc/id_createvnc_computenode ${GUACAMOLE_HOME}/tomcat/

chown -R tomcat ${GUACAMOLE_HOME}/tomcat


# HACK!!
# cat scripts/tomcat9.service | sed s+/etc/guacamole+${GUACAMOLE_HOME}+g > /lib/systemd/system/tomcat9.service
# systemctl daemon-reload

# cp target/guacamole-create-vnc-1.3.0.jar ${GUACAMOLE_HOME}/extensions/
# service tomcat9 restart

# Local commands
for x in launch-vnc launch-vnc-for list-vnc stop-vnc read-vnc-passwd; do
    cp scripts/$x ${GUACAMOLE_HOME}/
done

# Compute node commands
for x in list-vnc run-vnc stop-vnc; do
    scp scripts/$x cn001:${GUACAMOLE_HOME}/
done

# Symlinks for Slurm commands
for x in sbatch sinfo; do
    ln -s $(which $x) ${GUACAMOLE_HOME}/
done

# Symlinks for Slurm commands, on the compute nodes
for x in scancel; do
    ssh cn001 ln -s $(which $x) ${GUACAMOLE_HOME}/
done

touch ${GUACAMOLE_HOME}/guacamole.properties
