package com.atlassian.spnego;

import java.security.Principal;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.confluence.user.ConfluenceUser;
import com.atlassian.seraph.config.SecurityConfig;

public class ConfluenceSpnegoAuthenticator extends ConfluenceAuthenticator implements SpnegoAuthenticator {

	private static final long serialVersionUID = 1L;

	private static final Logger LOG = LoggerFactory.getLogger(ConfluenceSpnegoAuthenticator.class);

	private final SpnegoSupport support = new SpnegoSupport();

	@Override
	public final void init(final Map<String, String> params, final SecurityConfig config) {
		super.init(params, config);
		support.init(params);
	}

	@Override
	public Logger getLogger() {
		return LOG;
	}

	@Override
	public SpnegoSupport getSupport() throws IllegalStateException {
		return support.check();
	}

	@Override
	public ConfluenceUser getUser(final String userName) {
		return super.getUser(userName);
	}

	@Override
	public Principal getUserFromSession(final HttpServletRequest request) {
		return super.getUserFromSession(request);
	}

	@Override
	public final Principal getUser(final HttpServletRequest request, final HttpServletResponse response) {
		return getUserViaSPNEGO(request, response);
	}

	@Override
	public boolean authoriseUserAndEstablishSession(final HttpServletRequest request,
			final HttpServletResponse response, final Principal user) {
		if (super.authoriseUserAndEstablishSession(request, response, user)) {
			if (response != null) {
				getRememberMeService().addRememberMeCookie(request, response, user.getName());
			}
			return true;
		}
		return false;
	}
}
