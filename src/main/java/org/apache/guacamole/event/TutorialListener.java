package org.apache.guacamole.event;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.event.AuthenticationFailureEvent;
import org.apache.guacamole.net.event.AuthenticationSuccessEvent;
import org.apache.guacamole.net.event.listener.Listener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Listener that logs authentication success and failure events.
 */
public class TutorialListener implements Listener {

        private static final Logger logger =
	    LoggerFactory.getLogger(TutorialListener.class);

        @Override
	public void handleEvent(Object event) throws GuacamoleException {

	    if (event instanceof AuthenticationSuccessEvent) {
		logger.info("XXX successful authentication for user {}",
			    ((AuthenticationSuccessEvent) event)
			    .getCredentials().getUsername());
	    }
	    else if (event instanceof AuthenticationFailureEvent) {
		logger.info("XXX failed authentication for user {}",
			    ((AuthenticationFailureEvent) event)
			    .getCredentials().getUsername());
	    }
	}

}
