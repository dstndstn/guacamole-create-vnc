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
    private long cachedConnDirTime;
    private Directory<Connection> cachedConnDir;

    public CreateVNCAuthenticator() throws GuacamoleException {
        this.logger = LoggerFactory.getLogger((Class)CreateVNCAuthenticator.class);
        this.cachedConnDirTime = 0L;
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
        return (UserContext)new CreateVNCUserContext((AuthenticationProvider)this, authenticatedUser.getIdentifier(), cred.getPassword());
    }

        private class CreateVNCUserContext extends AbstractUserContext
        {
            private final Logger logger;
            private final AuthenticationProvider authProvider;
            private final String username;
            private final String password;
            private final boolean interpretTokens;

            public CreateVNCUserContext(final AuthenticationProvider authProvider, final String username, final String password) {
                this.logger = LoggerFactory.getLogger((Class)CreateVNCUserContext.class);
                this.authProvider = authProvider;
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
                return this.authProvider;
            }

            public Directory<Connection> getConnectionDirectory() throws GuacamoleException {
                final long now = System.currentTimeMillis();
                this.logger.info("getConnectionDirectory() for " + this.username + ": cached " + CreateVNCAuthenticator.this.cachedConnDirTime + ", now " + now + ", diff " + (now - CreateVNCAuthenticator.this.cachedConnDirTime));
                if (now - CreateVNCAuthenticator.this.cachedConnDirTime < 2000L && CreateVNCAuthenticator.this.cachedConnDir != null) {
                    this.logger.info("getConnectionDirectory() for " + this.username + ": cache hit");
                    return CreateVNCAuthenticator.this.cachedConnDir;
                }
                this.logger.info("getConnectionDirectory() for " + this.username + " (cache miss; querying)");


                this.logger.info("List all VNC sessions:");
                try {
                    Vector<GuacamoleConfiguration> allconfigs = CreateVNCAuthenticator.listVncSessions(CreateVNCAuthenticator.this.environment);
                    for (int i=0; i<allconfigs.size(); i++) {
                        GuacamoleConfiguration conf = allconfigs.get(i);
                        this.logger.info("Found: " + conf.getParameter("username") + " on host " + conf.getParameter("hostname") + " port " + conf.getParameter("port"));
                    }

                } catch (IOException e) {
                    this.logger.info("CreateVNCAuthenticator: failed to list VNC sessions: " + e.toString());
                }

                final Map<String, GuacamoleConfiguration> configs = this.getUserConfigs(this.username);
                final Map<String, Connection> connections = new ConcurrentHashMap<String, Connection>(configs.size());
                for (final Map.Entry<String, GuacamoleConfiguration> configEntry : configs.entrySet()) {
                    final String identifier = configEntry.getKey();
                    final GuacamoleConfiguration config = configEntry.getValue();
                    final Connection connection = (Connection)new SimpleConnection(identifier, identifier, config, this.interpretTokens);
                    connection.setParentIdentifier("ROOT");
                    connections.put(identifier, connection);
                }
                final GuacamoleConfiguration conf = new GuacamoleConfiguration();
                conf.setProtocol("vnc");
                conf.setParameter("username", this.username);
                conf.setParameter("password", this.password);
                final String identifier2 = "Launch & Connect to new remote desktop";
                final Connection connection2 = (Connection)new DynamicVNCConnection(identifier2, identifier2, conf, this.interpretTokens);
                connection2.setParentIdentifier("ROOT");
                connections.put(identifier2, connection2);
                final Directory<Connection> conn = (Directory<Connection>)new SimpleDirectory((Map)connections);
                this.logger.info("getConnectionDirectory() for " + this.username + " took " + (System.currentTimeMillis() - now) + " ms");
                CreateVNCAuthenticator.this.cachedConnDir = conn;
                CreateVNCAuthenticator.this.cachedConnDirTime = now;
                return conn;
            }

            public Map<String, GuacamoleConfiguration> getUserConfigs(final String username) {
                final Map<String, GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();
                GuacamoleConfiguration conf = null;
                conf = new GuacamoleConfiguration();
                conf.setProtocol("ssh");
                conf.setParameter("hostname", "localhost");
                conf.setParameter("username", username);
                conf.setParameter("password", this.password);
                configs.put("SSH", conf);
                /*
                conf = new GuacamoleConfiguration();
                conf.setProtocol("ssh");
                conf.setParameter("hostname", "localhost");
                conf.setParameter("username", username);
                conf.setParameter("password", this.password);
                conf.setParameter("command", "/bin/bash --norc --noprofile -i " + CreateVNCAuthenticator.this.environment.getGuacamoleHome() + "/start-vnc");
                configs.put("Create a new Remote Desktop (VNC)", conf);

                try {
                    final Process process = Runtime.getRuntime().exec(CreateVNCAuthenticator.this.environment.getGuacamoleHome() + "/list-vnc-for " + username + " --remote");
                    final BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line = null;
                    while ((line = r.readLine()) != null) {
                        final String[] words = line.split(" ");
                        if (words.length < 2) {
                            continue;
                        }
                        String port = words[0];
                        if (!port.startsWith(":")) {
                            continue;
                        }
                        port = port.substring(1);
                        final int portnum = Integer.parseInt(port);
                        final boolean guac = words[1].equals("T");
                        conf = new GuacamoleConfiguration();
                        conf.setProtocol("vnc");
                        conf.setParameter("hostname", "localhost");
                        conf.setParameter("port", Integer.toString(portnum + 5900));
                        if (guac) {
                            conf.setParameter("password", "GUAC");
                        }
                        configs.put("Connect to Remote Desktop #" + port, conf);
                        conf = new GuacamoleConfiguration();
                        conf.setProtocol("ssh");
                        conf.setParameter("hostname", "localhost");
                        conf.setParameter("username", username);
                        conf.setParameter("password", this.password);
                        conf.setParameter("command", "/bin/bash --norc --noprofile -i " + CreateVNCAuthenticator.this.environment.getGuacamoleHome() + "/stop-vnc " + port);
                        configs.put("Kill Remote Desktop #" + port, conf);
                    }
                }
                catch (IOException e) {
                    this.logger.info("CreateVNCAuthenticator: failed to list VNC sessions: " + e.toString());
                }
                 */
                conf = new GuacamoleConfiguration();
                conf.setProtocol("ssh");
                conf.setParameter("hostname", "localhost");
                conf.setParameter("username", username);
                conf.setParameter("password", this.password);
                conf.setParameter("command", "/bin/bash --norc -i " + CreateVNCAuthenticator.this.environment.getGuacamoleHome() + "/launch-vnc");
                configs.put("Launch a new Remote Desktop (VNC)", conf);

                try {
                    final Process process = Runtime.getRuntime().exec(CreateVNCAuthenticator.this.environment.getGuacamoleHome() + "/list-vnc-for " + username + " --remote");
                    final BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line = null;
                    while ((line = r.readLine()) != null) {
                        final String[] words = line.split(" ");
                        if (words.length < 3) {
                            continue;
                        }
                        String port = words[0];
                        if (!port.startsWith(":")) {
                            continue;
                        }
                        port = port.substring(1);
                        final int portnum = Integer.parseInt(port);
                        final boolean guac = words[1].equals("T");
                        final String host = words[2];
                        conf = new GuacamoleConfiguration();
                        conf.setProtocol("vnc");
                        conf.setParameter("hostname", host);
                        conf.setParameter("port", Integer.toString(portnum + 5900));
                        if (guac) {
                            conf.setParameter("password", "GUAC");
                        }
                        configs.put("Connect to Remote Desktop on cn001 #" + port, conf);
                    }
                }
                catch (IOException e) {
                    this.logger.info("CreateVNCAuthenticator: failed to list VNC sessions: " + e.toString());
                }
                return configs;
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

            GuacamoleConfiguration conf = new GuacamoleConfiguration();
            conf.setParameter("hostname", host);
            conf.setParameter("port", Integer.toString(portnum + 5900));
            conf.setParameter("username", user);
            confs.add(conf);
            //if (guac) {
            //conf.setParameter("password", "GUAC");
            //}
        }
        return confs;
    }

}
