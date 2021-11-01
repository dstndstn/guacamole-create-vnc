package com.github.dstndstn.guacamole;

import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.protocol.GuacamoleConfiguration;

import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;

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

    //private UserMapping getUserMapping() {
    //}
    private Map<String, GuacamoleConfiguration> getUserConfigs(String username) {
        logger.info("CreateVNCAuthenticator: getUserConfigs() for " + username);
        Map<String,GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();

        GuacamoleConfiguration conf = new GuacamoleConfiguration();
        conf.setProtocol("ssh");
        conf.setParameter("hostname", "localhost");
        conf.setParameter("username", username);
        configs.put("SSH", conf);

        try {
            conf = new GuacamoleConfiguration();
            conf.setProtocol("ssh");
            conf.setParameter("hostname", "localhost");
            conf.setParameter("username", "create-vnc");
            Path privkeyfilename = Paths.get(environment.getGuacamoleHome() + "/create-vnc/id_createvnc");
            String privkey = Files.readString(privkeyfilename);
            conf.setParameter("private-key", privkey);
            conf.setParameter("command", "/etc/guacamole/start-vnc-for " + username);
            configs.put("Create new Remote Desktop (VNC)", conf);
        } catch (IOException e) {
            logger.info("CreateVNCAuthenticator: failed to add Create new Virtual Desktop connection: " + e.toString());
        }

        // Find VNC sessions for this user.
        try {
            Process process = Runtime.getRuntime().exec("/etc/guacamole/list-vnc-for " + username);
            BufferedReader r =  new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = null;
            while((line=r.readLine())!=null) {
                logger.info("Found VNC entry: " + line);

                String[] words = line.split(" ");
                if (words.length < 2)
                    continue;
                String port = words[0];
                if (!port.startsWith(":"))
                    continue;
                boolean guac = (words[1] == "T");
                conf = new GuacamoleConfiguration();
                conf.setProtocol("vnc");
                conf.setParameter("hostname", "localhost");
                conf.setParameter("port", port);
                if (guac)
                    conf.setParameter("password", "GUAC");
                configs.put("Remote Desktop #" + port.substring(1), conf);
            }
        } catch (IOException e) {
            logger.info("CreateVNCAuthenticator: failed to list VNC sessions: " + e.toString());
        }

        return configs;
    }
    
    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials cred) throws GuacamoleException {
        Map<String, GuacamoleConfiguration> configs = null;

        logger.info("getAuthorizedConfigurations() called for create-vnc");

        //UserMapping userMapping = getUserMapping();
        //if (userMapping != null) {
        // Validate user and return the associated connections
        try {
            //String serviceName = userMapping.getServiceName();
            String serviceName = "guacamole";
            String userName = cred.getUsername();
            UnixUser user = new PAM(serviceName).authenticate(userName, cred.getPassword());
            if (user != null) {
                //configs = userMapping.getConfigurations(userName, user.getGroups());
                configs = getUserConfigs(userName);
                if (configs.isEmpty()) {
                    logger.info("No connections configured for user \"{}\".", userName);
                }
            }
        } catch (PAMException e) {
            // Fall through
        }
        //}
        logger.info("getAuthConfigs(): returning " + configs);
        return configs;
    }

    @Override
    public AuthenticatedUser updateAuthenticatedUser(AuthenticatedUser authenticatedUser,
                                                     Credentials credentials)
        throws GuacamoleException {
        logger.info("CreateVNCAuthenticator::updateAuthenticatedUser()");
        //return authenticateUser(credentials);

        logger.info("current auser: " + authenticatedUser);
        logger.info("credentials: " + credentials);

        logger.info("prev credentials: " + authenticatedUser.getCredentials());

        logger.info("credentials: u: " + credentials.getUsername() + ", p: " + credentials.getPassword());
        Credentials cold = authenticatedUser.getCredentials();
        logger.info("prev credentials: u: " + cold.getUsername() + ", p: " + cold.getPassword());

        //if (authenticatedUser instanceof SimpleAuthenticatedUser) {
        //  SimpleAuthenticatedUser sau = (SimpleAuthenticatedUser)authenticatedUser;
        //logger.info("SimpleAU credentials: " + sau.getCredentials());
        //}

        AuthenticatedUser au = authenticateUser(cold);
        logger.info("updateAuthUser: got " + au);
        return au;

        //return authenticatedUser;
    }
    // SimpleAuthenticatedUser.configs
    

    
}
