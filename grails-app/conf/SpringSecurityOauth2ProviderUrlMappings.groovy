import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2AuthorizationEndpointException
import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2TokenEndpointException

class SpringSecurityOauth2ProviderUrlMappings {
	static mappings = {
		"/oauth/authorize"(uri:"/oauth/authorize.dispatch")
		"/oauth/token"(uri:"/oauth/token.dispatch")

        "500"(controller: "OAuth2Exception", action: "tokenEndpointExceptionHandler", exception: OAuth2TokenEndpointException)
        "500"(controller: "OAuth2Exception", action: "authorizationEndpointExceptionHandler", exception: OAuth2AuthorizationEndpointException)
	}
}
