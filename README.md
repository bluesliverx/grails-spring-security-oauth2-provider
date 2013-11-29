This plugin is an OAuth2 Provider based on the Spring Security OAuth libraries.  It is partially based off of Burt Beckwith's OAuth 
Provider plugin, which was never officially released.

While this plugin works for certain use cases, not all OAuth2 flows have been tested.  In particular, the following works and has 
been tested:

* The full flow of logging in with both users and clients using tokens and authorization codes

However, the following items have not been tested and may or may not work:

* Grant types besides `authorization_code` and `client_credentials`
* Protected resources via Spring OAuth2
** This is currently done with the Spring Security core methods (ie request maps, annotations, intercept maps)

## Setup

On install, a view is created at `grails-app/views/oauth/confirm.gsp`.  This view may be modified as desired, but the
location should match the `userApprovalEndpointUrl` setting discussed below.

## How to Use

### Register Clients in Configuration

Clients are configured using the default in memory client details service in an option in Config.groovy or an external configuration
file specified by `grails.config.locations`.  The following is an example of configuring a simple client with an ID
of `myId` and a secret key of `mySecret`:

```groovy
grails.plugin.springsecurity.oauthProvider.clients = [
	[
		clientId:"myId",
		clientSecret:"mySecret"
	]
]
```

Notice that the client configuration consists of a list of maps with each map representing a single configured client.
The properties which can be configured match the properties in the `org.springframework.security.oauth2.provider.BaseClientDetails`
class.  The only difference is the `webServerRedirectUri` has been renamed to `registeredRedirectUri` in order to be compatible
with newer releases of Spring Security OAuth2.  Default values have been configured for each property except for `clientId` and
`clientSecret` since these are unique for each configured client.  These default values are shown in the following code block with
their default values.  These default values may be modified by placing a line similar to the following in Config.groovy or an external
configuration file.

```groovy
grails.plugin.springsecurity.oauthProvider.defaultClientConfig.resourceIds = []
grails.plugin.springsecurity.oauthProvider.defaultClientConfig.authorizedGrantTypes = ["authorization_code", "refresh_token"]
grails.plugin.springsecurity.oauthProvider.defaultClientConfig.scope = []
grails.plugin.springsecurity.oauthProvider.defaultClientConfig.registeredRedirectUri = null
grails.plugin.springsecurity.oauthProvider.defaultClientConfig.authorities = []
grails.plugin.springsecurity.oauthProvider.defaultClientConfig.accessTokenValiditySeconds = []
grails.plugin.springsecurity.oauthProvider.defaultClientConfig.refreshTokenValiditySeconds = []
```

For example, with a default configuration option in Config.groovy of:

```groovy
grails.plugin.springsecurity.oauthProvider.defaultClientConfig.authorizedGrantTypes = ["implicit"]
```

And a client configuration of:

```groovy
grails.plugin.springsecurity.oauthProvider.clients = [
	[
		clientId:"myId",
		clientSecret:"mySecret"
	]
]
```

Will result in a client with an ID of `myId` and a single authorized grant type of `implicit`.  However, if the client configuration
was modified to the following:

```groovy
grails.plugin.springsecurity.oauthProvider.clients = [
	[
		clientId:"myId",
		clientSecret:"mySecret",
		authorizedGrantTypes:["authorization_code"]
	]
]
```

Then the resulting configured client `myId` would have a single authorized grant type of `authorization_code`.  In other words,
the default configuration is overridden by the individual client configuration.

Using this method, when the configuration changes, the entire list of clients is reloaded and replaces the old list.

### Registering Clients in Bootstrap

Clients may also be individually registered by using the `BaseClientDetails` class in combination with the `clientDetailsService`
bean in the Bootstrap process.  The following is an example of registering a client programmatically (to be run in the BootStrap of your application):

```groovy
import org.springframework.security.oauth2.provider.BaseClientDetails;

class BootStrap {
	def clientDetailsService
	
	def init = { servletContext ->
		def client = new BaseClientDetails()
		client.clientId = "clientId"
		client.clientSecret = "clientSecret"
		client.authorizedGrantTypes = ["authorization_code", "refresh_token", "client_credentials", "password", "implicit"]
		
		// Set the full contents of the client details service store to the newly created client
		clientDetailsService.clientDetailsStore = [
			// Map of client ID to the client details instance
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

* The user must be logged into the application protected by this plugin.  Alternatively, they will be logged in
on the next step since the `authorizationEndpointUrl` must be protected with Spring Security Core.  One way to accomplish this
is to use the static rules in Config.groovy:

```groovy
grails.plugin.springsecurity.controllerAnnotations.staticRules = [
	'/oauth/authorize.dispatch':['ROLE_ADMIN'],
]
```

> Note that the URL is mapped with `.dispatch` at the end.  This is essential in order to correctly protect the resource.  For
> example, a `authorizationEndpointUrl` of `/custom/authorize-oauth2` would need to be protected with `/custom/authorize-oauth2.dispatch`.

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

* The client captures this code and sends it to the application at the `tokenEndpointUrl` setting.  
This will allow the client to access the application as the user.  Notice the `grant_type` of `authorization_code` this time.

```
http://localhost:8080/app/oauth/token?grant_type=authorization_code&client_id=clientId&code=OVD8SZ&redirect_uri=http://localhost:8080/app/
```

This will then give a token to the client that can be used to access the application as the user (an example needs to go here).

> WARNING: The redirect_uri in the `code` response and the `authorization_code` grant must match!  Otherwise, the authorization will fail.

#### Scribe Example

The groovy script below may be very useful in implementing the User Approval of Clients flow above.

```
import org.scribe.builder.*;
import org.scribe.builder.api.*;
import org.scribe.model.*;
import org.scribe.oauth.*;
import org.scribe.extractors.*;
import org.scribe.exceptions.*;
import org.scribe.utils.*;

@Grab(group='org.scribe', module='scribe', version='1.3.5')

class GrailsOAuth20Api extends DefaultApi20 {
    @Override
    public String getAccessTokenEndpoint() {
        return "http://localhost:8080/test-oauth/oauth/token?grant_type=authorization_code&redirect_uri=http://localhost:8081/test-oauth-client/test/verify";
    }

    @Override
    public String getAuthorizationUrl(OAuthConfig oAuthConfig) {
        return "http://localhost:8080/test-oauth/oauth/authorize?response_type=code&client_id=1&client_secret=secret&redirect_uri=http://localhost:8081/test-oauth-client/test/verify";
    }
	
	@Override
	public AccessTokenExtractor getAccessTokenExtractor() {
		return new GrailsTokenExtractor();
	}
}

public class GrailsTokenExtractor implements AccessTokenExtractor {
  private static final TOKEN_REGEX = ~/"access_token":\s*"([^"]+)"/;
  private static final String EMPTY_SECRET = '';

  /**
   * {@inheritDoc} 
   */
  public Token extract(String response) {
    Preconditions.checkEmptyString(response, "Response body is incorrect. Can't extract a token from an empty string");

	def matcher = TOKEN_REGEX.matcher(response);
    if (matcher.find()) {
      String token = OAuthEncoder.decode(matcher.group(1));
      return new Token(token, EMPTY_SECRET, response);
    } else {
      throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'", null);
    }
  }
}
final String PROTECTED_RESOURCE_URL = "http://localhost:8080/test-oauth/book/list";
final Token EMPTY_TOKEN = new Token('', '')

// If you choose to use a callback, "oauth_verifier" will be the return value by Twitter (request param)
OAuthService service = new ServiceBuilder()
                            .provider(GrailsOAuth20Api.class)
                            .apiKey("1")
                            .apiSecret("secret")
                            .build();
Scanner in2 = new Scanner(System.in);

System.out.println("=== Grails OAuth2 Provider Workflow ===");
System.out.println();

System.out.println("Now go and authorize Scribe here:");
System.out.println(service.getAuthorizationUrl(EMPTY_TOKEN));
System.out.println("And paste the verifier here");
System.out.print(">>");
Verifier verifier = new Verifier(in2.nextLine());
System.out.println();

// Trade the Verifier for the Access Token
System.out.println("Trading the Verifier for an Access Token...");
Token accessToken = service.getAccessToken(EMPTY_TOKEN, verifier);
System.out.println("Got the Access Token!");
System.out.println("(if you're curious it looks like this: " + accessToken + " )");
System.out.println();

// Now let's go and ask for a protected resource!
System.out.println("Now we're going to access a protected resource...");
OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
service.signRequest(accessToken, request);
Response response = request.send();
System.out.println("Got it! Lets see what we found...");
System.out.println();
System.out.println(response.getBody());

System.out.println();
System.out.println("Thats it! Go and build something awesome with Scribe!");
```

### Protecting Resources

If the instructions above are followed, this plugin will provide access to resources protected with the `Secured` annotation or with
static rules defined in Config.groovy.  Resources protected with request maps or other spring security configurations *should* be protected,
but is untested.  If you have tested this plugin in these configurations, please let me know and I'll update this section.

## Configuration

### Endpoint URLs

By default, three endpoint URLs have been defined.  Note that default URLMappings are provided for the 
`authorizationEndpointUrl` and the `tokenEndpointUrl`.  If these are modified, additional URLMappings will have to
be set.  Their default values and how they would be set in Config.groovy are shown below:

```groovy
grails.plugin.springsecurity.oauthProvider.authorizationEndpointUrl = "/oauth/authorize"
grails.plugin.springsecurity.oauthProvider.tokenEndpointUrl = "/oauth/token"	// Where the client is authorized
grails.plugin.springsecurity.oauthProvider.userApprovalEndpointUrl = "/oauth/confirm"	// Where the user confirms that they approve the client
```

NOTE: The `userApprovalEndpointUrl` never is actually redirected to, but is simply used to specify the location of the view.
For example, a `userApprovalEndpointUrl` of `/custom/oauth_confirm` would map to the `grails-app/views/custom/oauth_confirm.gsp` view.

### Grant Types

The grant types for OAuth authentication may be enabled or disabled with simple configuration options.  By default all grant types are enabled.
Set the option to false to disable it completely, regardless of client configuration.

```groovy
grails.plugin.springsecurity.oauthProvider.grantTypes.authorizationCode = true
grails.plugin.springsecurity.oauthProvider.grantTypes.implicit = true
grails.plugin.springsecurity.oauthProvider.grantTypes.refreshToken = true
grails.plugin.springsecurity.oauthProvider.grantTypes.clientCredentials = true
grails.plugin.springsecurity.oauthProvider.grantTypes.password = true
```

### Configuration

Here are some other configuration options that can be set and their default values.  Again, these would be placed in Config.groovy:

```groovy
grails.plugin.springsecurity.oauthProvider.active = true // Set to false to disable the provider, true in all environments but test where false is the default
grails.plugin.springsecurity.oauthProvider.filterStartPosition = SecurityFilterPosition.X509_FILTER.order // The starting location of the filters registered
grails.plugin.springsecurity.oauthProvider.userApprovalParameterName = "user_oauth_approval" // Used on the user confirmation page (see userApprovalEndpointUrl)
grails.plugin.springsecurity.oauthProvider.tokenServices.refreshTokenValiditySeconds = 60 * 10 //default 10 minutes
grails.plugin.springsecurity.oauthProvider.tokenServices.accessTokenValiditySeconds = 60 * 60 * 12 //default 12 hours
grails.plugin.springsecurity.oauthProvider.tokenServices.reuseRefreshToken = true
grails.plugin.springsecurity.oauthProvider.tokenServices.supportRefreshToken = true
```
