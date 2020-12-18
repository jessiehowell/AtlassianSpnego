package com.atlassian.spnego;

import java.security.Principal;
import java.util.Map;

import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.security.login.LoginStore;
import com.atlassian.jira.user.ApplicationUser;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.atlassian.jira.security.login.JiraSeraphAuthenticator;
import com.atlassian.seraph.config.SecurityConfig;

public class JiraSpnegoAuthenticator extends JiraSeraphAuthenticator implements SpnegoAuthenticator {

	private static final long serialVersionUID = 1L;

	private static final Logger LOG = LoggerFactory.getLogger(JiraSpnegoAuthenticator.class);

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
	public Principal getUser(final String userName) {
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
			ApplicationUser appUser = ComponentAccessor.getUserManager().getUserByName(user.getName());
      LoginStore loginStore = ComponentAccessor.getComponentOfType(LoginStore.class);
		if (super.authoriseUserAndEstablishSession(request, response, user)) {
			if (response != null) {
				getRememberMeService().addRememberMeCookie(request, response, user.getName());
			}
			loginStore.recordLoginAttempt(appUser, true);
			return true;
		}
		loginStore.recordLoginAttempt(appUser, false);
		return false;
	}
}
