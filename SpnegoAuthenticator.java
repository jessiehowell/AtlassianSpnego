package com.atlassian.spnego;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;

public interface SpnegoAuthenticator {

	Logger getLogger();

	SpnegoSupport getSupport() throws IllegalStateException;

	Principal getUser(final String userName);

	Principal getUserFromSession(final HttpServletRequest request);

	boolean authoriseUserAndEstablishSession(final HttpServletRequest request, final HttpServletResponse response,
			final Principal user);

	default public Principal getUserViaSPNEGO(final HttpServletRequest request, final HttpServletResponse response) {

		// check if the user is already logged in and use the current principal
		Principal user = getUserFromSession(request);
		if (user != null) {
			getLogger().trace("Already logged in as: {}", user.getName());
			return user;
		}

		// we need a servlet response to respond with required authentication type
		if (response == null) {
			getLogger().trace("No response object in request for URI '{}' - no negotiation possible",
					request.getRequestURI());
			return null;
		}

		// skip excluded URI - but only if it's not an included URI
		if (getSupport().isIncludedUri(request)) {
			if (getLogger().isDebugEnabled()) {
				String queryString = request.getQueryString() != null ? "?" + request.getQueryString() : "";
				getLogger().debug("Including URI '{}{}'", request.getRequestURI(), queryString);
			}
		} else if (getSupport().isExcludedUri(request)) {
			if (getLogger().isDebugEnabled()) {
				String queryString = request.getQueryString() != null ? "?" + request.getQueryString() : "";
				getLogger().debug("Excluding URI '{}{}'", request.getRequestURI(), queryString);
			}
			return null;
		}

		// if no authentication header of type "Negotiate" present then request one
		if (!getSupport().hasNegotiationAuthenticationHeader(request, response)) {
			getLogger().debug("No authentication header in request for URI '{}' - starting negotiation",
					request.getRequestURI());
			return null;
		}

		// authenticate via SPNEGO
		String userName = getSupport().authenticate(request, response);
		if (userName != null) {
			user = getUser(userName);
			if (user == null) {
				getLogger().warn("User not found: {}", userName);
				return null;
			}
			getLogger().info("Authenticated user: {}", user);
			if (!authoriseUserAndEstablishSession(request, response, user)) {
				getLogger().warn("User not authorized: " + userName);
			}
		}
		return user;
	}
}