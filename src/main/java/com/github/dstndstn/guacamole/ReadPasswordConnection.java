package com.github.dstndstn.guacamole;

import java.io.Reader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import org.apache.guacamole.net.GuacamoleTunnel;
import java.util.Map;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.LocalEnvironment;
import org.slf4j.LoggerFactory;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.net.auth.simple.SimpleConnection;

public class ReadPasswordConnection extends SimpleConnection
{
    private final Environment environment;
    private final Logger logger;

    public ReadPasswordConnection(final String name, final String identifier, final GuacamoleConfiguration config, final boolean interpretTokens) throws GuacamoleException {
        super(name, identifier, config, interpretTokens);
        this.logger = LoggerFactory.getLogger((Class)ReadPasswordConnection.class);
        this.environment = (Environment)new LocalEnvironment();
    }

    public GuacamoleTunnel connect(final GuacamoleClientInformation info, final Map<String, String> tokens) throws GuacamoleException {
        this.logger.info("ReadPasswordConnection.connect()");
        final GuacamoleConfiguration conf = this.getFullConfiguration();
        //this.logger.info("  config: " + conf.getParameters().toString());
        final String username = conf.getParameter("username");

        final String passwd_fn = conf.getParameter("vnc-password-file");
        String passwd = readPasswordFile(username, passwd_fn);
        if (passwd != null) {
            conf.setParameter("password", passwd);
            //logger.info("Set VNC password: " + passwd);
        }
        //this.logger.info("Connecting with config: " + conf.getParameters().toString());
        return super.connect(info, (Map)tokens);
    }

    protected String readPasswordFile(final String username, final String filename) {
        //this.logger.info("readPasswordFile: " + username + ", " + filename);
        try {
            final Process process = Runtime.getRuntime().exec(this.environment.getGuacamoleHome() + "/read-vnc-passwd " + username + " " + filename);
            final BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = null;
            while ((line = r.readLine()) != null) {
                //this.logger.info("  " + line);
                return line;
            }
        } catch (IOException e) {
            this.logger.info("Failed to read VNC password: " + e.toString());
        }
        return null;
    }
}
