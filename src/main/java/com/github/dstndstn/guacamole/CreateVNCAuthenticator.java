package com.github.dstndstn.guacamole;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.Reader;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.simple.SimpleDirectory;
import org.apache.guacamole.net.auth.simple.SimpleConnection;
import org.apache.guacamole.net.auth.simple.SimpleObjectPermissionSet;
import org.apache.guacamole.net.auth.simple.SimpleUser;
import org.apache.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.apache.guacamole.net.auth.permission.ObjectPermissionSet;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.protocol.GuacamoleConfiguration;

import org.jvnet.libpam.UnixUser;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.PAM;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

public class CreateVNCAuthenticator extends SimpleAuthenticationProvider
{
    private final Logger logger;
    private final Environment environment;
    private long cachedConnTime;
    private Vector<GuacamoleConfiguration> cachedConn;

    public CreateVNCAuthenticator() throws GuacamoleException {
        this.logger = LoggerFactory.getLogger((Class)CreateVNCAuthenticator.class);
        this.cachedConnTime = 0L;
        this.logger.info("CreateVNCAuthenticator() constructor");
        this.environment = (Environment)new LocalEnvironment();
    }
    
    public String getIdentifier() {
        return "create-vnc";
    }

    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(final Credentials cred) throws GuacamoleException {
        if (!this.pamCheckCredentials(cred)) {
            return null;
        }
        return new HashMap<String, GuacamoleConfiguration>();
    }

    private boolean pamCheckCredentials(final Credentials cred) {
        try {
            final String serviceName = "guacamole";
            final UnixUser user = new PAM(serviceName).authenticate(cred.getUsername(), cred.getPassword());
            if (user != null) {
                return true;
            }
        }
        catch (PAMException ex) {}
        return false;
    }

    public UserContext getUserContext(final AuthenticatedUser authenticatedUser) throws GuacamoleException {
        final Credentials cred = authenticatedUser.getCredentials();
        if (!this.pamCheckCredentials(cred)) {
            return null;
        }
        return (UserContext)new CreateVNCUserContext(this, authenticatedUser.getIdentifier(), cred.getPassword());
    }

    public Vector<GuacamoleConfiguration> getSessions() {
        final long now = System.currentTimeMillis();
        this.logger.info("getSessions(): cached " + (now - cachedConnTime) + " ms ago");
        if (now - cachedConnTime < 2000L && cachedConn != null) {
            this.logger.info("cache hit!");
            return cachedConn;
        }
        this.logger.info("cache miss -- listing all VNC sessions");
        try {
            Vector<GuacamoleConfiguration> allconfigs = CreateVNCAuthenticator.listVncSessions(environment);
            for (int i=0; i<allconfigs.size(); i++) {
                GuacamoleConfiguration conf = allconfigs.get(i);
                this.logger.info("Found: " + conf.getParameter("username") + " on host " + conf.getParameter("hostname") + " port " + conf.getParameter("port"));
            }
            cachedConn = allconfigs;
            cachedConnTime = now;
        } catch (IOException e) {
            this.logger.info("CreateVNCAuthenticator: failed to list VNC sessions: " + e.toString());
        }
        return cachedConn;
    }
    
    private class CreateVNCUserContext extends AbstractUserContext {
        private final Logger logger;
        private final CreateVNCAuthenticator parent;
        private final String username;
        private final String password;
        private final boolean interpretTokens;

        public CreateVNCUserContext(CreateVNCAuthenticator parent,
                                    final String username, final String password) {
            this.logger = LoggerFactory.getLogger((Class)CreateVNCUserContext.class);
            this.parent = parent;
            this.username = username;
            this.password = password;
            this.interpretTokens = true;
        }

        public User self() {
            return (User)new SimpleUser(this.username) {
                    public ObjectPermissionSet getConnectionGroupPermissions() throws GuacamoleException {
                        return (ObjectPermissionSet)new SimpleObjectPermissionSet((Collection)CreateVNCUserContext.this.getConnectionDirectory().getIdentifiers());
                    }
                    public ObjectPermissionSet getConnectionPermissions() throws GuacamoleException {
                        return (ObjectPermissionSet)new SimpleObjectPermissionSet((Collection)CreateVNCUserContext.this.getConnectionGroupDirectory().getIdentifiers());
                    }
                };
        }

        public Object getResource() throws GuacamoleException {
            return null;
        }

        public AuthenticationProvider getAuthenticationProvider() {
            return (AuthenticationProvider)this.parent;
        }

        
        public Directory<Connection> getConnectionDirectory() throws GuacamoleException {
            Vector<GuacamoleConfiguration> configs = parent.getSessions();
            Connection connection = null;
            GuacamoleConfiguration conf = null;
            String ident = null;
            final Map<String, Connection> connections = new ConcurrentHashMap<String, Connection>(configs.size());
            for (int i=0; i<configs.size(); i++) {
                conf = configs.get(i);
                if (!conf.getParameter("username").equals(this.username))
                    continue;
                ident = "Connect to Remote Desktop on " +
                    conf.getParameter("hostname") + " #" + conf.getParameter("shortport");
                String pwfn = conf.getParameter("vnc-password-file");
                if (pwfn != null) {
                    connection = (Connection)new ReadPasswordConnection(ident, ident, conf,
                                                                        this.interpretTokens);
                } else {
                    connection = (Connection)new SimpleConnection(ident, ident, conf,
                                                                  this.interpretTokens);
                }
                connection.setParentIdentifier("ROOT");
                connections.put(ident, connection);

                GuacamoleConfiguration conf2 = new GuacamoleConfiguration();
                conf2.setProtocol("ssh");
                conf2.setParameter("hostname", conf.getParameter("hostname"));
                conf2.setParameter("username", this.username);
                conf2.setParameter("password", this.password);
                conf2.setParameter("command", "/bin/bash --norc -i " + parent.environment.getGuacamoleHome() + "/stop-vnc " + conf.getParameter("shortport"));
                ident = "Stop Remote Desktop " +
                    conf.getParameter("hostname") + " #" + conf.getParameter("shortport");
                connection = (Connection)new SimpleConnection(ident, ident, conf2,
                                                              this.interpretTokens);
                connection.setParentIdentifier("ROOT");
                connections.put(ident, connection);

            }
            conf = new GuacamoleConfiguration();
            conf.setProtocol("vnc");
            conf.setParameter("username", this.username);
            conf.setParameter("password", this.password);
            ident = "Launch & Connect to new remote desktop";
            connection = (Connection)new DynamicVNCConnection(ident, ident, conf,
                                                              this.interpretTokens);
            connection.setParentIdentifier("ROOT");
            connections.put(ident, connection);

            conf = new GuacamoleConfiguration();
            conf.setProtocol("ssh");
            conf.setParameter("hostname", "localhost");
            conf.setParameter("username", username);
            conf.setParameter("password", this.password);
            //conf.setParameter("command", "/bin/bash --norc -i " + CreateVNCAuthenticator.this.environment.getGuacamoleHome() + "/launch-vnc");
            conf.setParameter("command", parent.environment.getGuacamoleHome() + "/launch-vnc");
            ident = "Launch a new Remote Desktop (VNC)";
            connection = (Connection)new SimpleConnection(ident, ident, conf,
                                                          this.interpretTokens);
            connection.setParentIdentifier("ROOT");
            connections.put(ident, connection);

            conf = new GuacamoleConfiguration();
            conf.setProtocol("ssh");
            conf.setParameter("hostname", "localhost");
            conf.setParameter("username", username);
            conf.setParameter("password", this.password);
            ident = "SSH";
            connection = (Connection)new SimpleConnection(ident, ident, conf,
                                                          this.interpretTokens);
            connection.setParentIdentifier("ROOT");
            connections.put(ident, connection);
            
            final Directory<Connection> conn = (Directory<Connection>)new SimpleDirectory((Map)connections);
            return conn;
        }
    }

    
    public static Vector<GuacamoleConfiguration> listVncSessions(Environment env)
    throws IOException {
        Logger logger = LoggerFactory.getLogger((Class)CreateVNCAuthenticator.class);
        Vector<GuacamoleConfiguration> confs = new Vector<GuacamoleConfiguration>();
        
        final Process process = Runtime.getRuntime().exec(env.getGuacamoleHome() +
                                                          "/list-vnc-all --remote");
        final BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line = null;
        while ((line = r.readLine()) != null) {
            logger.info("  " + line);
            final String[] words = line.split(" ");
            if (words.length < 3) {
                continue;
            }
            final String host = words[0];
            String port = words[1];
            if (!port.startsWith(":")) {
                continue;
            }
            port = port.substring(1);
            final int portnum = Integer.parseInt(port);
            final boolean guac = words[1].equals("T");
            String user = words[2];

            String passwd_fn = null;
            if (words.length > 3)
                passwd_fn = words[3];

            GuacamoleConfiguration conf = new GuacamoleConfiguration();
            conf.setProtocol("vnc");
            conf.setParameter("hostname", host);
            conf.setParameter("port", Integer.toString(portnum + 5900));
            conf.setParameter("shortport", Integer.toString(portnum));
            conf.setParameter("username", user);
            conf.setParameter("vnc-password-file", passwd_fn);
            confs.add(conf);
        }
        return confs;
    }

}
