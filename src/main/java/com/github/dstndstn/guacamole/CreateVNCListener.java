package com.github.dstndstn.guacamole;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.event.AuthenticationFailureEvent;
import org.apache.guacamole.net.event.AuthenticationSuccessEvent;
import org.apache.guacamole.net.event.listener.Listener;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.properties.StringGuacamoleProperty;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;


/**
 * A Listener that logs authentication success and failure events.
 */
public class CreateVNCListener implements Listener {

    private static final Logger logger =
	LoggerFactory.getLogger(CreateVNCListener.class);

    /**
     * Guacamole server environment.
     */
    private final Environment environment;

    public static StringGuacamoleProperty UPDATE_VNC_LIST = new StringGuacamoleProperty()
        {
            @Override
            public String getName() { return "update-vnc-list"; }
        };

    public CreateVNCListener() throws GuacamoleException {
	environment = new LocalEnvironment();
    }

    @Override
    public void handleEvent(Object event) throws GuacamoleException {

	if (event instanceof AuthenticationSuccessEvent) {
	    logger.info("Successful authentication for user {}",
			((AuthenticationSuccessEvent) event)
			.getCredentials().getUsername());
            String updatevnclist = environment.getProperty(UPDATE_VNC_LIST);
            if (updatevnclist == null) {
                updatevnclist = environment.getGuacamoleHome() + "/update-vnc-list";
            } else if (!updatevnclist.startsWith("/")) {
                updatevnclist = environment.getGuacamoleHome() + "/" + updatevnclist;
            }
            String cmd = updatevnclist + " " + ((AuthenticationSuccessEvent) event).getCredentials().getUsername();
            logger.info("Running: " + cmd);
	    try {
		Runtime run = Runtime.getRuntime();
		Process pr = run.exec(cmd);
		//logger.info("Process: " + pr.toString());
		int rtn = pr.waitFor();
		logger.info("Return value " + String.valueOf(rtn));
		BufferedReader buf = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		String line = "";
		while ((line=buf.readLine())!=null)
		    logger.info(line);
	    } catch (Exception e) {
		logger.info("Failed to run " + updatevnclist + ":");
		logger.info(e.toString());
	    }
	}
	else if (event instanceof AuthenticationFailureEvent) {
	    logger.info("Failed authentication for user {}",
			((AuthenticationFailureEvent) event)
			.getCredentials().getUsername());
	}
    }
}
