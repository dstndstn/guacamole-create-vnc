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

public class DynamicVNCConnection extends SimpleConnection
{
    private final Environment environment;
    private final Logger logger;

    public DynamicVNCConnection(final String name, final String identifier, final GuacamoleConfiguration config, final boolean interpretTokens) throws GuacamoleException {
        super(name, identifier, config, interpretTokens);
        this.logger = LoggerFactory.getLogger((Class)DynamicVNCConnection.class);
        this.environment = (Environment)new LocalEnvironment();
    }

    public GuacamoleTunnel connect(final GuacamoleClientInformation info, final Map<String, String> tokens) throws GuacamoleException {
        this.logger.info("DynamicVNCConnection.connect()");
        final GuacamoleConfiguration conf = this.getFullConfiguration();
        this.logger.info("  config: " + conf.getParameters().toString());
        final String username = conf.getParameter("username");
        try {
            if (this.findVncSessionFor(username, conf)) {
                this.logger.info("Found existing VNC sessions, setting config: " + conf.getParameters().toString());
                return super.connect(info, (Map)tokens);
            }
        }
        catch (IOException e) {
            this.logger.info("Failed to list VNC sessions: " + e.toString());
        }
        this.logger.info("Launching new VNC session...");
        try {
            final Process process = Runtime.getRuntime().exec(this.environment.getGuacamoleHome() + "/launch-vnc-for " + username);
            final BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = null;
            while ((line = r.readLine()) != null) {
                this.logger.info(line);
            }
        }
        catch (IOException e) {
            this.logger.info("Failed to launch VNC session for " + username + ": " + e.toString());
        }
        this.logger.info("Launched a new VNC session for " + username + "!");
        for (int i = 0; i < 5; ++i) {
            try {
                if (this.findVncSessionFor(username, conf)) {
                    this.logger.info("Found existing VNC sessions, setting config: " + conf.getParameters().toString());
                    return super.connect(info, (Map)tokens);
                }
            }
            catch (IOException e2) {
                this.logger.info("Failed to list VNC sessions: " + e2.toString());
            }
            try {
                Thread.sleep(2000L);
            }
            catch (InterruptedException ex) {}
        }
        return super.connect(info, (Map)tokens);
    }

    private boolean findVncSessionFor(final String username, final GuacamoleConfiguration conf) throws IOException {
        this.logger.info("findVncSessionFor:");
        final Process process = Runtime.getRuntime().exec(this.environment.getGuacamoleHome() + "/list-vnc-for " + username + " --remote");
        final BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line = null;
        while ((line = r.readLine()) != null) {
            this.logger.info("  " + line);
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
            conf.setParameter("hostname", host);
            conf.setParameter("port", Integer.toString(portnum + 5900));
            if (guac) {
                conf.setParameter("password", "GUAC");
            }
            return true;
        }
        return false;
    }
}
