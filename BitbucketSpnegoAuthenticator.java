package com.atlassian.spnego;

import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import com.atlassian.bitbucket.auth.*;
import com.atlassian.bitbucket.i18n.I18nService;
import com.atlassian.bitbucket.server.StorageService;
import com.atlassian.bitbucket.user.*;

import java.security.Principal;
import java.util.Map;
import java.util.Properties;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BitbucketSpnegoAuthenticator implements HttpAuthenticationHandler, HttpAuthenticationSuccessHandler
{
  private static final Logger log = LoggerFactory.getLogger(BitbucketSpnegoAuthenticator.class);
  private static final boolean logDebug = false;
  
  private final SpnegoSupport support = new SpnegoSupport();
  
  private static final String authContainerUserName = "auth.container.remote-user";
  
  private final I18nService i18nService; 
	private final UserService userService;
	private final StorageService storageService;

	public BitbucketSpnegoAuthenticator(@ComponentImport final I18nService i18nService, @ComponentImport final UserService userService, @ComponentImport final StorageService storageService)
	{
		this.i18nService = i18nService;
		this.userService = userService;
		this.storageService = storageService;
		support.init(getProps());
	}
	
	private Map<String, String> getProps()
	{
    Properties props = new Properties();
    String propsDirName = storageService.getHomeDir().toString();
    String propsFileName = "spnego.properties";
    File propsFile = new File(propsDirName, propsFileName);
    FileInputStream propsStream;
    
    try
    {
      propsStream = new FileInputStream(propsFile);
      props.load(propsStream);
    }
    catch (IOException ex)
    {
      log.error("Unable to open properties file: " + propsDirName + "\\" + propsFileName);
    }
    return (Map)props;
	}
	
	public String getUserViaSPNEGO(HttpServletRequest request, HttpServletResponse response)
	{
    if (response == null) 
    {
			log.trace("No response object in request for URI '{}' - no negotiation possible", request.getRequestURI());
			return null;
		}

		// skip excluded URI - but only if it's not an included URI
		if (support.isIncludedUri(request)) 
		{
			if (logDebug) {
				String queryString = request.getQueryString() != null ? "?" + request.getQueryString() : "";
				log.debug("Including URI '{}{}'", request.getRequestURI(), queryString);
			}
		} 
		else if (support.isExcludedUri(request)) 
		{
			if (logDebug)
			{
				String queryString = request.getQueryString() != null ? "?" + request.getQueryString() : "";
				log.debug("Excluding URI '{}{}'", request.getRequestURI(), queryString);
			}
			return null;
		}

		// if no authentication header of type "Negotiate" present then request one
		if (!support.hasNegotiationAuthenticationHeader(request, response)) 
		{
			log.debug("No authentication header in request for URI '{}' - starting negotiation", request.getRequestURI());
			return null;
		}

		// authenticate via SPNEGO
		String userName = support.authenticate(request, response);
		return userName;
	}
	@Override
	public AuthenticationResult performAuthentication(HttpAuthenticationContext httpAuthenticationContext)
	{
    ApplicationUser user = this.authenticate(httpAuthenticationContext);
    if (user == null)
    {
      return null;
    }
    return new AuthenticationResult.Builder(user).build();
	}
	
	public ApplicationUser authenticate(HttpAuthenticationContext httpAuthenticationContext)
	{
    HttpServletRequest request = httpAuthenticationContext.getRequest();
    HttpServletResponse response = httpAuthenticationContext.getResponse();
    
    String authUser = getUserViaSPNEGO(request, response);
    ApplicationUser user = userService.getUserByName(authUser);
    if (authUser != null) 
    {
      request.setAttribute(authContainerUserName, authUser);
    }
    else
    {
      log.error("User " + authUser + " not allowed to login.");
    }

    return user;
	}
	
	@Override
	public void validateAuthentication(HttpAuthenticationContext httpAuthenticationContext)
	{
    HttpServletRequest request = httpAuthenticationContext.getRequest();
    HttpServletResponse response = httpAuthenticationContext.getResponse();
    HttpSession session = request.getSession(false);
    
    if (session == null)
    {
      return;
    }
    
    String sessionUser = (String)session.getAttribute(authContainerUserName);
    String remoteUser = getUserViaSPNEGO(request, response);
    
    if (sessionUser == "null")
    {
      return;
    }
    
    if (sessionUser != null && !sessionUser.equals(remoteUser))
		{
			log.error("container.auth.usernamenomatch Session username " + remoteUser + " does not match username provided by the container " + sessionUser);
			throw new ExpiredAuthenticationException(i18nService.getKeyedText("container.auth.usernamenomatch", "Session username {0} does not match username provided by the container {1}", sessionUser, remoteUser));
		}
	}
	
	@Override
	public boolean onAuthenticationSuccess(HttpAuthenticationSuccessContext context) throws ServletException, IOException
	{
    String authUser = (String)context.getRequest().getAttribute(authContainerUserName);
		if (authUser != null)
		{
			context.getRequest().getSession().setAttribute(authContainerUserName, authUser);
			if (logDebug)
			{
        log.info("Added " + authUser + " as " + authContainerUserName + " to session.");
      }
		}
		else
		{
      if (logDebug)
      {
        log.warn("Request " + authContainerUserName + " was not set / null.");
      }
		}

		return false;
  }
}
