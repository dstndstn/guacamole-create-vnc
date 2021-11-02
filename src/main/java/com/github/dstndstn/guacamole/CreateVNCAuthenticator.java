package com.github.dstndstn.guacamole;

import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.apache.guacamole.net.auth.permission.ObjectPermissionSet;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.apache.guacamole.net.auth.simple.SimpleUserContext;
import org.apache.guacamole.net.auth.simple.SimpleDirectory;
import org.apache.guacamole.net.auth.simple.SimpleConnection;
import org.apache.guacamole.net.auth.simple.SimpleUser;
import org.apache.guacamole.net.auth.simple.SimpleObjectPermissionSet;

import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CreateVNCAuthenticator extends SimpleAuthenticationProvider {

    private final Logger logger = LoggerFactory.getLogger(CreateVNCAuthenticator.class);
    private final Environment environment;

    public CreateVNCAuthenticator() throws GuacamoleException {
        logger.info("CreateVNCAuthenticator() constructor");
        environment = new LocalEnvironment();
    }

    @Override
    public String getIdentifier() {
        return "create-vnc";
    }

    /* We need to create our own UserContext that dynamically
     * generates the list of Connections available to each user.
     *
     * Because Reasons, SimpleUserContext is not subclassable for our
     * purposes, hence this copy-n-edit.
     */
    private class CreateVNCUserContext extends AbstractUserContext {
        private final Logger logger = LoggerFactory.getLogger(CreateVNCUserContext.class);

        private final AuthenticationProvider authProvider;
        private final String username;
        private final String password;
        private final boolean interpretTokens;
        public CreateVNCUserContext(AuthenticationProvider authProvider,
                                    String username,
                                    String password) {
            this.authProvider = authProvider;
            this.username = username;
            this.password = password;
            this.interpretTokens = true;
        }
        @Override
        public User self() {
            return new SimpleUser(username) {
                @Override
                public ObjectPermissionSet getConnectionGroupPermissions() throws GuacamoleException {
                    return new SimpleObjectPermissionSet(getConnectionDirectory().getIdentifiers());
                }
                @Override
                public ObjectPermissionSet getConnectionPermissions() throws GuacamoleException {
                    return new SimpleObjectPermissionSet(getConnectionGroupDirectory().getIdentifiers());
                }
            };
        }
        @Override
        public Object getResource() throws GuacamoleException {
            return null;
        }
        @Override
        public AuthenticationProvider getAuthenticationProvider() {
            return authProvider;
        }
        @Override
        public Directory<Connection> getConnectionDirectory()
            throws GuacamoleException {
            logger.info("getConnectionDirectory() for " + username);
            Map<String, GuacamoleConfiguration> configs = getUserConfigs(username);
            Map<String, Connection> connections = new ConcurrentHashMap<String, Connection>(configs.size());
            for (Map.Entry<String, GuacamoleConfiguration> configEntry : configs.entrySet()) {
                String identifier = configEntry.getKey();
                GuacamoleConfiguration config = configEntry.getValue();
                Connection connection = new SimpleConnection(identifier, identifier, config, interpretTokens);
                connection.setParentIdentifier(DEFAULT_ROOT_CONNECTION_GROUP);
                connections.put(identifier, connection);
            }
            return new SimpleDirectory<Connection>(connections);
        }

        public Map<String, GuacamoleConfiguration> getUserConfigs(String username) {
            //logger.info("CreateVNCAuthenticator: getUserConfigs() for " + username);
            Map<String,GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();
            GuacamoleConfiguration conf = null;
            conf = new GuacamoleConfiguration();
            conf.setProtocol("ssh");
            conf.setParameter("hostname", "localhost");
            conf.setParameter("username", username);
            conf.setParameter("password", password);
            configs.put("SSH", conf);
            // We used to ssh as a special system user that could sudo... but we've got the user's
            // username & password, so we can just do it directly...
            // try {
            //     conf = new GuacamoleConfiguration();
            //     conf.setProtocol("ssh");
            //     conf.setParameter("hostname", "localhost");
            //     conf.setParameter("username", "create-vnc");
            //     Path privkeyfilename = Paths.get(environment.getGuacamoleHome() + "/create-vnc/id_createvnc");
            //     String privkey = Files.readString(privkeyfilename);
            //     conf.setParameter("private-key", privkey);
            //     conf.setParameter("command", environment.getGuacamoleHome() + "/start-vnc-for " + username);
            //     configs.put("Create a new Remote Desktop (VNC)", conf);
            // } catch (IOException e) {
            //     logger.info("CreateVNCAuthenticator: failed to add Create new Virtual Desktop connection: " + e.toString());
            // }

            conf = new GuacamoleConfiguration();
            conf.setProtocol("ssh");
            conf.setParameter("hostname", "localhost");
            conf.setParameter("username", username);
            conf.setParameter("password", password);
            conf.setParameter("command", "/bin/bash --norc --noprofile -i " + environment.getGuacamoleHome() + "/start-vnc");
            configs.put("Create a new Remote Desktop (VNC)", conf);


            
            // Find VNC sessions for this user.
            try {
                Process process = Runtime.getRuntime().exec(environment.getGuacamoleHome() + "/list-vnc-for " + username);
                BufferedReader r =  new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line = null;
                while((line=r.readLine())!=null) {
                    //logger.info("Found VNC entry: " + line);
                    String[] words = line.split(" ");
                    if (words.length < 2)
                        continue;
                    String port = words[0];
                    if (!port.startsWith(":"))
                        continue;
                    port = port.substring(1);
                    //logger.info("Trimmed port to: " + port);
                    int portnum = Integer.parseInt(port);
                    boolean guac = words[1].equals("T");
                    conf = new GuacamoleConfiguration();
                    conf.setProtocol("vnc");
                    conf.setParameter("hostname", "localhost");
                    conf.setParameter("port", Integer.toString(portnum + 5900));
                    if (guac) {
                        conf.setParameter("password", "GUAC");
                    }
                    //logger.info("VNC config: " + conf.toString());
                    configs.put("Connect to Remote Desktop #" + port, conf);

                    conf = new GuacamoleConfiguration();
                    conf.setProtocol("ssh");
                    conf.setParameter("hostname", "localhost");
                    conf.setParameter("username", username);
                    conf.setParameter("password", password);
                    conf.setParameter("command", "/bin/bash --norc --noprofile -i " + environment.getGuacamoleHome() + "/stop-vnc " + port);
                    configs.put("Kill Remote Desktop #" + port, conf);

                }
            } catch (IOException e) {
                logger.info("CreateVNCAuthenticator: failed to list VNC sessions: " + e.toString());
            }


            conf = new GuacamoleConfiguration();
            conf.setProtocol("ssh");
            conf.setParameter("hostname", "localhost");
            conf.setParameter("username", username);
            conf.setParameter("password", password);
            conf.setParameter("command", "/bin/bash --norc -i " + environment.getGuacamoleHome() + "/launch-vnc");
            configs.put("Launch a new Remote Desktop (VNC)", conf);

            // Find Remote VNC sessions for this user.
            try {
                Process process = Runtime.getRuntime().exec(environment.getGuacamoleHome() + "/list-vnc-for " + username + " --remote");
                BufferedReader r =  new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line = null;
                while((line=r.readLine())!=null) {
                    //logger.info("Found VNC entry: " + line);
                    String[] words = line.split(" ");
                    if (words.length < 3)
                        continue;
                    String port = words[0];
                    if (!port.startsWith(":"))
                        continue;
                    port = port.substring(1);
                    //logger.info("Trimmed port to: " + port);
                    int portnum = Integer.parseInt(port);
                    boolean guac = words[1].equals("T");
                    String host = words[2];
                    conf = new GuacamoleConfiguration();
                    conf.setProtocol("vnc");
                    // FIXME
                    conf.setParameter("hostname", host);
                    conf.setParameter("port", Integer.toString(portnum + 5900));
                    if (guac) {
                        conf.setParameter("password", "GUAC");
                    }
                    configs.put("Connect to Remote Desktop on cn001 #" + port, conf);

                    // conf = new GuacamoleConfiguration();
                    // conf.setProtocol("ssh");
                    // conf.setParameter("hostname", "localhost");
                    // conf.setParameter("username", username);
                    // conf.setParameter("password", password);
                    // conf.setParameter("command", "/bin/bash --norc --noprofile -i " + environment.getGuacamoleHome() + "/stop-vnc " + port);
                    // configs.put("Kill Remote Desktop #" + port, conf);

                }
            } catch (IOException e) {
                logger.info("CreateVNCAuthenticator: failed to list VNC sessions: " + e.toString());
            }



            return configs;
        }
    }

    /*
    private class SimpleAuthenticatedUser extends AbstractAuthenticatedUser {
        private final Credentials credentials;
        private final Map<String, GuacamoleConfiguration> configs;
        public SimpleAuthenticatedUser(Credentials credentials, Map<String, GuacamoleConfiguration> configs) {
            // Store credentials and configurations
            this.credentials = credentials;
            this.configs = configs;
            // Pull username from credentials if it exists
            String username = credentials.getUsername();
            if (username != null && !username.isEmpty())
                setIdentifier(username);
            // Otherwise generate a random username
            else
                setIdentifier(UUID.randomUUID().toString());
        }
        public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations() {
            return configs;
        }
        @Override
        public AuthenticationProvider getAuthenticationProvider() {
            return SimpleAuthenticationProvider.this;
        }
        @Override
        public Credentials getCredentials() {
            return credentials;
        }
        @Override
        public Set<String> getEffectiveUserGroups() {
            return Collections.<String>emptySet();
        }
    }
     */

    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials cred) throws GuacamoleException {
        //Map<String, GuacamoleConfiguration> configs = null;
        if (!pamCheckCredentials(cred)) {
            return null;
        }
        return new HashMap<String, GuacamoleConfiguration>();
    }

    private boolean pamCheckCredentials(Credentials cred) {
        try {
            String serviceName = "guacamole";
            UnixUser user = new PAM(serviceName).authenticate(cred.getUsername(),
                                                              cred.getPassword());
            if (user != null) {
                return true;
            }
        } catch (PAMException e) {
            // Fall through
        }
        return false;
    }
    
    // copied from SimpleAuthenticationProvider -- use a different
    // UserContext subclass.
    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
        throws GuacamoleException {
        Credentials cred = authenticatedUser.getCredentials();
        if (!pamCheckCredentials(cred))
            return null;
        return new CreateVNCUserContext(this, authenticatedUser.getIdentifier(),
                                        cred.getPassword());
    }

    
    /*
    @Override
    public AuthenticatedUser authenticateUser(final Credentials credentials)
        throws GuacamoleException {
        Credentials cred = authenticatedUser.getCredentials();
        if (!pamCheckCredentials(cred))
            return null;
        Map<String,GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();
        return new SimpleAuthenticatedUser(credentials, configs);
    }
     */

}
