import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.ClientRegistrationException

class SpringSecurityOauth2ProviderUrlMappings {
	static mappings = {
		"/oauth/authorize"(uri:"/oauth/authorize.dispatch")
		"/oauth/token"(uri:"/oauth/token.dispatch")

        "500"(controller: "OAuth2Exception", action: "clientRegistrationExceptionHandler", exception: ClientRegistrationException)
        "500"(controller: "OAuth2Exception", action: "oAuth2ExceptionHandler", exception: OAuth2Exception)
	}
}
