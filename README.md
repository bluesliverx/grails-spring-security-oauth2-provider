This plugin is an OAuth2 Provider based on the spring security libraries.  It is based off of Burt Beckwith's OAuth Provider plugin (never officially released).

NOTE: This plugin is incomplete still and does not provide full functionality.  The full flow of logging in with both users and clients work, but there
still remains no way for the resources to be protected in a manner matching that of the Spring Security Core 'Secured' annotations.

## How to Use

### OAuth Controller/View

The `user.confirmUrl` setting controls where the user will be redirected to confirm access to a certain client

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

## Login Flows

### Client Login

The client may login with the URL given in the `client.authUrl` setting (`/oauth/authorize` by default) by using the following syntax.
Notice the `grant_type` of `client_credentials` and that the client credentials from the example above are used.

```
http://localhost:8080/app/oauth/authorize?grant_type=client_credentials&response_type=code&client_id=clientId&client_secret=clientSecret
```

The response from a login such as this is the following JSON.  The `access_token` is the important piece here.

```javascript
{
  "access_token": "449acfe6-663f-4fde-b1f8-414c867a4cb5",
  "expires_in": 43200,
  "refresh_token": "ab12ce7a-de9d-48db-a674-0044897074b0"
}
```

### User Approval of Clients

The following URLs or configuration options show a typical flow authorizing a client for a certain user.

* The client must first be logged in using the URL above.
* Separately, the client must be logged into the application protected by OAuth.  Alternatively, they will be logged in
on the next step since the `user.confirmUrl` is protected or *should* be protected with a Spring Security Core `Secured`
annotation.
* A user attempting to use a service provided by the OAuth protected application through the client reaches the client.  The
client then redirects the user to the `user.authUrl` setting (`/oauth/user/authorize` by default).  This will actually
redirect the user to the `user.confirmUrl` setting which will present the user with an option to authorize or deny access
to the client to the application.

```
http://localhost:8080/app/oauth/user/authorize?response_type=code&client_id=clientId&redirect_uri=http://localhost:8080/app/
```

The user will then be redirected to the `redirect_uri` with the code appended as a URL parameter such as:

```
http://localhost:8080/app/?code=YjZOa8
```

* The client captures this code and sends it to the application at the `client.authUrl` setting.  
This will allow the client to access the application as the user.  Notice the `grant_type` of `authorization_code` this time.

```
http://localhost:8080/app/oauth/authorize?grant_type=authorization_code&client_id=clientId&code=OVD8SZ&redirect_uri=http://localhost:8080/app/
```

This will then give a token to the client that can be used to access the application as the user (an example needs to go here).

### Protecting Resources

This section of the plugin still needs work to tie in the Spring Security Core `Secured` annotation or intercept URL map or Request Map definitions
with the OAuth provider concept of protected resources.

## Configuration

### URLs

By default, URLs have been defined.  Their default values and how they would be set in Config.groovy are shown below:

```groovy
grails.plugins.springsecurity.oauthProvider.user.authUrl = "/oauth/user/authorize" // Where the user is authorized
grails.plugins.springsecurity.oauthProvider.client.authUrl = "/oauth/authorize" // Where the client is authorized
grails.plugins.springsecurity.oauthProvider.user.confirmUrl = "/oauth/confirm" // Where the user confirms that they approve the client
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