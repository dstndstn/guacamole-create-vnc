package com.github.dstndstn.guacamole;

import java.io.Reader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Map;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.simple.SimpleConnection;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;

public class DynamicVNCConnection extends ReadPasswordConnection /*SimpleConnection*/
{
    private final Environment environment;
    private final Logger logger;
    private final CreateVNCAuthenticator parent;

    public DynamicVNCConnection(final String name, final String identifier, final GuacamoleConfiguration config,
                                final boolean interpretTokens, CreateVNCAuthenticator parent) throws GuacamoleException {
        super(name, identifier, config, interpretTokens);
        this.logger = LoggerFactory.getLogger((Class)DynamicVNCConnection.class);
        this.environment = (Environment)new LocalEnvironment();
        //this.environment = (Environment)LocalEnvironment.getInstance();
        this.parent = parent;
    }

    public GuacamoleTunnel connect(final GuacamoleClientInformation info, final Map<String, String> tokens) throws GuacamoleException {
        this.logger.info("DynamicVNCConnection.connect()");
        final GuacamoleConfiguration conf = this.getFullConfiguration();
        this.logger.info("  full config: " + conf.getParameters().toString());
        this.logger.info("  config: " + this.getConfiguration().getParameters().toString());
        final String username = conf.getParameter("username");

        // Check for an existing VNC session.  If none found, launch a new one.
        Vector<GuacamoleConfiguration> configs = this.parent.getSessions();
        //Connection connection = null;
        GuacamoleConfiguration c = null;
        boolean found = false;
        for (int i=0; i<configs.size(); i++) {
            c = configs.get(i);
            if (!c.getParameter("username").equals(username))
                continue;
            this.logger.info("Found existing VNC session: " +
                             c.getParameter("hostname") + " #" + c.getParameter("shortport"));
            this.logger.info("Config: " + c.getParameters().toString());
            for (Map.Entry<String,String> entry : c.getParameters().entrySet()) {
                conf.setParameter(entry.getKey(), entry.getValue());
            }
            found = true;
        }

        if (!found) {
            this.logger.info("Launching new VNC session...");
            String host = null;
            int port = -1;
            String passwdfn = null;
            try {
                final Process process = Runtime.getRuntime().exec(this.environment.getGuacamoleHome() + "/launch-vnc-for " + username);
                final BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line = null;
                while ((line = r.readLine()) != null) {
                    this.logger.info(line);
                    final String[] words = line.split(" ");
                    /* Look for lines like:
                     VNCHost cn002
                     VNCPort 29
                     VNCPasswordFile /home/dlang/.vnc/passwd-guac-234567.txt
                     */
                    if (words.length < 2)
                        continue;
                    if (words[0].equals("VNCHost"))
                        host = words[1];
                    if (words[0].equals("VNCPort"))
                        port = Integer.parseInt(words[1]);
                    if (words[0].equals("VNCPasswordFile"))
                        passwdfn = words[1];
                }
            }
            catch (IOException e) {
                this.logger.info("Failed to launch VNC session for " + username + ": " + e.toString());
            }
            this.logger.info("Launched a new VNC session for " + username + "!");

            if ((host != null) && (port > -1)) {
                conf.setParameter("hostname", host);
                conf.setParameter("port", Integer.toString(port + 5900));
                if (passwdfn != null)
                    conf.setParameter("vnc-password-file", passwdfn);
            }
        }

        return super.connect(info, (Map)tokens);
    }
}
