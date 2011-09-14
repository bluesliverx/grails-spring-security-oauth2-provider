This plugin is an OAuth2 Provider based on the spring security libraries.  It is based off of Burt Beckwith's OAuth Provider plugin (never officially released).

## How to Use

### Register Clients

This is an example of registering a client (to be run in the BootStrap of your application):
def clientDetailsService

```groovy
import org.springframework.security.oauth2.provider.BaseClientDetails;

class BootStrap {
	def clientDetailsService
	
	def init = { servletContext ->
		def client = new BaseClientDetails()
		client.clientId = "clientId"
		client.clientSecret = "clientSecret"
		client.authorizedGrantTypes = ["authorization_code", "refresh_token", "client_credentials"]
		clientDetailsService.clientDetailsStore = [
			"clientId":client
		]
	}
```

## Configuration

### URLs

By default, URLs have been defined.  Their default values and how they would be set in Config.groovy are shown below:

```groovy
grails.plugins.springsecurity.oauthProvider.user.authUrl = "/oauth/user/authorize" // Where the user is authorized
grails.plugins.springsecurity.oauthProvider.client.authUrl = "/oauth/authorize" // Where the client is authorized
grails.plugins.springsecurity.oauthProvider.user.confirmUrl = "/login/confirm" // Where the user confirms that they approve the client
```

### Custom Beans

The following beans by default are constructed for you.  However, if an alternate implementation is desired to be used, override the configuration setting
for the bean names and define a custom bean in spring/resources.groovy or spring/resources.xml.

```groovy
// Type org.springframework.security.oauth2.provider.verification.DefaultClientAuthenticationCache by default, use any class with the same implemented interface
grails.plugins.springsecurity.oauthProvider.verificationCode = "oauthClientAuthenticationCache" // Bean name of the client authentication cache
// Type org.springframework.security.oauth2.provider.verification.InMemoryVerificationCodeServices by default, use any class with the same implemented interface
grails.plugins.springsecurity.oauthProvider.verificationCode = "oauthVerificationCodeServices" // Bean name of the verification code services
```

### Configuration

Here are some other configuration options that can be set and their default values.  Again, these would be placed in Config.groovy:

```groovy
grails.plugins.springsecurity.oauthProvider.active = true // Set to false to disable the provider
grails.plugins.springsecurity.oauthProvider.user.approvalParameter = "user_oauth_approval" // Used in the user approval filter
grails.plugins.springsecurity.oauthProvider.user.approvalParameterValue = true
grails.plugins.springsecurity.oauthProvider.tokenServices.tokenSecretLengthBytes = 80 // Length of secret token by default
grails.plugins.springsecurity.oauthProvider.tokenServices.refreshTokenValiditySeconds = 60 * 10 //default 10 minutes
grails.plugins.springsecurity.oauthProvider.tokenServices.accessTokenValiditySeconds = 60 * 60 * 12 //default 12 hours
grails.plugins.springsecurity.oauthProvider.tokenServices.reuseRefreshToken = true
grails.plugins.springsecurity.oauthProvider.tokenServices.supportRefreshToken = true
```