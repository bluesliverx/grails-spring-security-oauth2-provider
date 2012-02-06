This plugin is an OAuth2 Provider based on the spring security libraries.  It is based off of Burt Beckwith's OAuth Provider plugin (never officially released).

NOTE: This plugin is incomplete still and does not provide full functionality.  Teh following works and has been at least partially tested:
* The full flow of logging in with both users and clients using tokens and authorization codes
However, the following items have not been tested and may or may not work:
* Grant types besides `authorization_code` and `client_credentials`
* Protected resources via spring OAuth2 protection - this is simply done with the Spring Security core methods as of now

## Setup

A few steps are required before the plugin is ready for use.  First, add the necessary URL mappings to URLMappings.groovy:

```groovy
"/oauth/authorize"(uri:"/oauth/authorize.dispatch")
"/oauth/token"(uri:"/oauth/token.dispatch")
```

Note that these URLs should match the `tokenEndpointUrl` and `authorizationEndpointUrl` settings discussed below.
Additionally, the confirm.gsp view should exist in `views/oauth/confirm.gsp`.

## How to Use

### OAuth Controller/View

The `userApprovalEndpointUrl` setting controls where the user will be redirected to confirm access to a certain client

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
		client.authorizedGrantTypes = ["authorization_code", "refresh_token", "client_credentials", "password", "implicit"]
		clientDetailsService.clientDetailsStore = [
			"clientId":client
		]
	}
```

## Login Flows

### Client Login

The client may login with the URL given in the `tokenEndpointUrl` setting (`/oauth/token` by default) by using the following syntax.
Notice the `grant_type` of `client_credentials` and that the client credentials from the example above are used.

```
http://localhost:8080/app/oauth/token?grant_type=client_credentials&client_id=clientId&client_secret=clientSecret
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
* Separately, the client must be logged into the application protected by this plugin.  Alternatively, they will be logged in
on the next step since the `authorizationEndpointUrl` must be protected with Spring Security Core.  One way to accomplish this
is to use the static rules in Config.groovy:
```groovy
grails.plugins.springsecurity.controllerAnnotations.staticRules = [
	'/oauth/authorize.dispatch':['ROLE_ADMIN'],
]
```
** Note that the URL is mapped with `.dispatch` at the end.  This is essential in order to correctly protect the resource.  For
example, a `authorizationEndpointUrl` of `/custom/authorize-oauth2` would need to be protected with `/custom/authorize-oauth2.dispatch`.
* A client attempting to use a service provided by the OAuth protected application is reached by a user.  The
client then redirects the user to the `authorizationEndpointUrl` setting (`/oauth/authorize` by default).  This will actually
redirect the user to the `userApprovalEndpointUrl` setting which will present the user with an option to authorize or deny access
to the application for the client.

```
http://localhost:8080/app/oauth/authorize?response_type=code&client_id=clientId&redirect_uri=http://localhost:8080/app/
```

The user will then be redirected to the `redirect_uri` with the code appended as a URL parameter such as:

```
http://localhost:8080/app/?code=YjZOa8
```

* The client captures this code and sends it to the application at the `authorizationEndpointUrl` setting.  
This will allow the client to access the application as the user.  Notice the `grant_type` of `authorization_code` this time.

```
http://localhost:8080/app/oauth/authorize?grant_type=authorization_code&client_id=clientId&code=OVD8SZ&redirect_uri=http://localhost:8080/app/
```

This will then give a token to the client that can be used to access the application as the user (an example needs to go here).

NOTE: The redirect_uri in the `code` response and the `authorization_code` grant must match!  Otherwise, the authorization will fail.

### Protecting Resources

If the instructions above are followed, this plugin will provide access to resources protected with the `Secured` annotation or with
static rules defined in Config.groovy.  Resources protected with request maps or other spring security configurations *should* be protected,
but is untested.  If you have tested this plugin in these configurations, please let me know and I'll update this section.

## Configuration

### Endpoint URLs

By default, three endpoint URLs have been defined.  Their default values and how they would be set in Config.groovy are shown below:

```groovy
grails.plugins.springsecurity.oauthProvider.authorizationEndpointUrl = "/oauth/authorize"
grails.plugins.springsecurity.oauthProvider.tokenEndpointUrl = "/oauth/token"	// Where the client is authorized
grails.plugins.springsecurity.oauthProvider.userApprovalEndpointUrl = "/oauth/confirm"	// Where the user confirms that they approve the client
```

### Grant Types

The grant types for OAuth authentication may be enabled or disabled with simple configuration options.  By default all grant types are enabled.
Set the option to false to disable it completely, regardless of client configuration.

```groovy
grails.plugins.springsecurity.oauthProvider.grantTypes.authorizationCode = true
grails.plugins.springsecurity.oauthProvider.grantTypes.implicit = true
grails.plugins.springsecurity.oauthProvider.grantTypes.refreshToken = true
grails.plugins.springsecurity.oauthProvider.grantTypes.clientCredentials = true
grails.plugins.springsecurity.oauthProvider.grantTypes.password = true
```

### Configuration

Here are some other configuration options that can be set and their default values.  Again, these would be placed in Config.groovy:

```groovy
grails.plugins.springsecurity.oauthProvider.active = true // Set to false to disable the provider, true in all environments but test where false is the default
grails.plugins.springsecurity.oauthProvider.filterStartPosition = SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order // The starting location of the filters registered
grails.plugins.springsecurity.oauthProvider.authorizationCode.approvalParameterName = "user_oauth_approval" // Used on the user confirmation page (see userApprovalEndpointUrl)
grails.plugins.springsecurity.oauthProvider.tokenServices.refreshTokenValiditySeconds = 60 * 10 //default 10 minutes
grails.plugins.springsecurity.oauthProvider.tokenServices.accessTokenValiditySeconds = 60 * 60 * 12 //default 12 hours
grails.plugins.springsecurity.oauthProvider.tokenServices.reuseRefreshToken = true
grails.plugins.springsecurity.oauthProvider.tokenServices.supportRefreshToken = true
```