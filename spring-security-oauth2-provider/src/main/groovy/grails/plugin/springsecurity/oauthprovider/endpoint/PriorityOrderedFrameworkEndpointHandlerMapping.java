package grails.plugin.springsecurity.oauthprovider.endpoint;

import org.springframework.core.PriorityOrdered;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;

public class PriorityOrderedFrameworkEndpointHandlerMapping extends FrameworkEndpointHandlerMapping implements PriorityOrdered {
}