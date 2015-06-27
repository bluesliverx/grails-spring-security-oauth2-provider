package test.oauth2

import helper.AccessTokenRequest
import helper.GrantTypes
import pages.LoginPage
import spock.lang.Ignore
import spock.lang.Unroll

class SecuredOAuth2ResourcesControllerFunctionalSpec extends AbstractAccessControlFunctionalSpec {

    void "invalid bearer token in request"() {
        when:
        def response = requestRawResponse('securedOAuth2Resources/clientRole', 'invalid-bearer-token')

        then:
        response.status == 401
        response.data.error == 'invalid_token'
    }

    @Unroll
    void "client has role expression for grant type [#grantType]"() {
        given:
        def request = new AccessTokenRequest(grantType: grantType, clientId: 'public-client')
        def token = getAccessToken(request)

        expect:
        attemptUnauthorizedResourceRequest('securedOAuth2Resources/clientRoleExpression')

        and:
        requestResource('securedOAuth2Resources/clientRoleExpression', token) == 'client role expression'

        where:
        _   |   grantType
        _   |   GrantTypes.AuthorizationCode
        _   |   GrantTypes.Implicit
        _   |   GrantTypes.ResourceOwnerCredentials
        _   |   GrantTypes.ClientCredentials
    }

    @Unroll
    void "traditional config client role denies grant type [#grantType]"() {
        given:
        def request = new AccessTokenRequest(grantType: grantType, clientId: 'public-client')
        def token = getAccessToken(request)

        expect:
        attemptUnauthorizedResourceRequest('securedOAuth2Resources/clientRole')

        and:
        forbiddenResource('securedOAuth2Resources/clientRole', token)

        where:
        _   |   grantType
        _   |   GrantTypes.AuthorizationCode
        _   |   GrantTypes.Implicit
        _   |   GrantTypes.ResourceOwnerCredentials
    }

    void "traditional config client role allows client credentials"() {
        given:
        def request = new AccessTokenRequest(grantType: GrantTypes.ClientCredentials, clientId: 'public-client')
        def token = getAccessToken(request)

        expect:
        attemptUnauthorizedResourceRequest('securedOAuth2Resources/clientRole')

        and:
        requestResource('securedOAuth2Resources/clientRole', token) == 'client role'
    }

    @Unroll
    void "client has any role expression for grant type [#grantType] and client [#clientId: #clientSecret]"() {
        given:
        def request = new AccessTokenRequest(grantType: grantType, clientId: clientId, clientSecret: clientSecret)
        def token = getAccessToken(request)

        expect:
        attemptUnauthorizedResourceRequest('securedOAuth2Resources/clientHasAnyRole')

        and:
        requestResource('securedOAuth2Resources/clientHasAnyRole', token) == 'client has any role'

        where:
        grantType                           |   clientId                |   clientSecret
        GrantTypes.AuthorizationCode        |   'public-client'         |   ''
        GrantTypes.AuthorizationCode        |   'confidential-client'   |   'secret-pass-phrase'

        GrantTypes.Implicit                 |   'public-client'         |   ''
        GrantTypes.Implicit                 |   'confidential-client'   |   'secret-pass-phrase'

        GrantTypes.ResourceOwnerCredentials |   'public-client'         |   ''
        GrantTypes.ResourceOwnerCredentials |   'confidential-client'   |   'secret-pass-phrase'

        GrantTypes.ClientCredentials        |   'public-client'         |   ''
        GrantTypes.ClientCredentials        |   'confidential-client'   |   'secret-pass-phrase'
    }

    @Unroll
    void "isClient() denies grant type [#grantType]"() {
        def request = new AccessTokenRequest(grantType: grantType, clientId: 'public-client')
        def token = getAccessToken(request)

        expect:
        attemptUnauthorizedResourceRequest('securedOAuth2Resources/client')

        and:
        forbiddenResource('securedOAuth2Resources/client', token)

        where:
        _   |   grantType
        _   |   GrantTypes.AuthorizationCode
        _   |   GrantTypes.Implicit
        _   |   GrantTypes.ResourceOwnerCredentials
    }

    @Unroll
    void "isClient() allows client credentials for client [#clientId: #clientSecret]"() {
        given:
        def request = new AccessTokenRequest(grantType: GrantTypes.ClientCredentials,
                clientId: clientId, clientSecret: clientSecret)
        def token = getAccessToken(request)

        expect:
        attemptUnauthorizedResourceRequest('securedOAuth2Resources/client')

        and:
        requestResource('securedOAuth2Resources/client', token) == 'is client'

        where:
        clientId                |   clientSecret
        'public-client'         |   ''
        'confidential-client'   |   'secret-pass-phrase'
    }

    @Unroll
    void "isUser() allows grant type [#grantType]"() {
        given:
        def request = new AccessTokenRequest(grantType: grantType, clientId: 'public-client')
        def token = getAccessToken(request)

        expect:
        attemptUnauthorizedResourceRequest('securedOAuth2Resources/user')

        and:
        requestResource('securedOAuth2Resources/user', token) == 'is user'

        where:
        _   |   grantType
        _   |   GrantTypes.AuthorizationCode
        _   |   GrantTypes.Implicit
        _   |   GrantTypes.ResourceOwnerCredentials
    }

    @Unroll
    void "isUser denies client credentials for client [#clientId: #clientSecret]"() {
        given:
        def request = new AccessTokenRequest(grantType: GrantTypes.ClientCredentials,
                clientId: clientId, clientSecret: clientSecret)
        def token = getAccessToken(request)

        expect:
        attemptUnauthorizedResourceRequest('securedOAuth2Resources/user')

        and:
        forbiddenResource('securedOAuth2Resources/user', token)

        where:
        clientId                |   clientSecret
        'public-client'         |   ''
        'confidential-client'   |   'secret-pass-phrase'
    }

    // TODO: Re-enable once the auth processing filter does not allow tokens to be omitted
    @Ignore()
    @Unroll
    void "denyOAuthClient() denies grant type [#grantType]"() {
        given:
        def request = new AccessTokenRequest(grantType: grantType, clientId: 'public-client')
        def token = getAccessToken(request)

        expect:
        attemptUnauthorizedResourceRequest('securedOAuth2Resources/denyClient')

        and:
        forbiddenResource('securedOAuth2Resources/denyClient', token)

        where:
        _   |   grantType
        _   |   GrantTypes.AuthorizationCode
        _   |   GrantTypes.Implicit
        _   |   GrantTypes.ResourceOwnerCredentials
        _   |   GrantTypes.ClientCredentials
    }

    // TODO: Re-evaluate this once auth processing filter works properly
    void "access web only resource secured with denyOAuthClient()"() {
        given:
        to LoginPage
        login()

        when:
        go 'securedOAuth2Resources/denyClient'

        then:
        $().text() == 'no client can see'
    }

    @Unroll
    void "permitAll is not affected by grantType [#grantType]"() {
        given:
        def request = new AccessTokenRequest(grantType: grantType, clientId: 'public-client')
        def token = getAccessToken(request)

        expect:
        requestResource('securedOAuth2Resources/anyone', token) == 'anyone can see'

        where:
        _   |   grantType
        _   |   GrantTypes.AuthorizationCode
        _   |   GrantTypes.Implicit
        _   |   GrantTypes.ResourceOwnerCredentials
        _   |   GrantTypes.ClientCredentials
    }

    void "permitAll allows token to be omitted"() {
        expect:
        requestResource('securedOAuth2Resources/anyone') == 'anyone can see'
    }

    void "permitAll allows web user"() {
        when:
        go 'securedOAuth2Resources/anyone'

        then:
        $().text() == 'anyone can see'

        when:
        to LoginPage
        login()

        and:
        go 'securedOAuth2Resources/anyone'

        then:
        $().text() == 'anyone can see'
    }

    @Unroll
    void "locked down endpoint cannot be accessed by grantType [#grantType]"() {
        given:
        def request = new AccessTokenRequest(grantType: grantType, clientId: 'public-client')
        def token = getAccessToken(request)

        expect:
        forbiddenResource('securedOAuth2Resources/nobody', token)

        where:
        _   |   grantType
        _   |   GrantTypes.AuthorizationCode
        _   |   GrantTypes.Implicit
        _   |   GrantTypes.ResourceOwnerCredentials
        _   |   GrantTypes.ClientCredentials
    }

    void "locked down endpoint cannot be accessed by web user"() {
        given:
        formLogin()

        when:
        go 'securedOAuth2Resources/nobody'

        then:
        page.contains('unauthorized')
    }

    @Unroll
    void "trusted client test for client [#clientId: #clientSecret] with grantType [#grantType] and scope [#scope] is allowed [#allowed]"() {
        given:
        def request = new AccessTokenRequest(grantType: grantType, clientId: clientId, clientSecret: clientSecret, scope: scope)
        def token = getAccessToken(request)

        expect:
        if(allowed) {
            requestResource('securedOAuth2Resources/trustedClient', token) == 'trusted client'
        }
        else {
            forbiddenResource('securedOAuth2Resources/trustedClient', token)
        }

        where:
        grantType                           |   clientId                |   clientSecret            |   scope       |   allowed
        GrantTypes.AuthorizationCode        |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   false
        GrantTypes.Implicit                 |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   false
        GrantTypes.ResourceOwnerCredentials |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   false
        GrantTypes.ClientCredentials        |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   true
        GrantTypes.ClientCredentials        |   'confidential-client'   |   'secret-pass-phrase'    |   'read'      |   false
    }

    @Unroll
    void "trusted user test for client [#clientId: #clientSecret] with grantType [#grantType] and scope [#scope] is allowed [#allowed]"() {
        given:
        def request = new AccessTokenRequest(grantType: grantType, clientId: clientId, clientSecret: clientSecret, scope: scope)
        def token = getAccessToken(request)

        expect:
        if(allowed) {
            requestResource('securedOAuth2Resources/trustedUser', token) == 'trusted user'
        }
        else {
            forbiddenResource('securedOAuth2Resources/trustedUser', token)
        }

        where:
        grantType                           |   clientId                |   clientSecret            |   scope       |   allowed
        GrantTypes.AuthorizationCode        |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   true
        GrantTypes.AuthorizationCode        |   'confidential-client'   |   'secret-pass-phrase'    |   'read'      |   false

        GrantTypes.Implicit                 |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   true
        GrantTypes.Implicit                 |   'confidential-client'   |   'secret-pass-phrase'    |   'read'      |   false

        GrantTypes.ResourceOwnerCredentials |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   true
        GrantTypes.ResourceOwnerCredentials |   'confidential-client'   |   'secret-pass-phrase'    |   'read'      |   false

        GrantTypes.ClientCredentials        |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   false
    }

    @Unroll
    void "role user or read scope test for client [#clientId: #clientSecret] with grantType [#grantType] and scope [#scope] is allowed [#allowed]"() {
        given:
        def request = new AccessTokenRequest(grantType: grantType, clientId: clientId, clientSecret: clientSecret, scope: scope)
        def token = getAccessToken(request)

        expect:
        if(allowed) {
            requestResource('securedOAuth2Resources/userRoleOrReadScope', token) == 'trusted user'
        }
        else {
            forbiddenResource('securedOAuth2Resources/userRoleOrReadScope', token)
        }

        where:
        grantType                           |   clientId                |   clientSecret            |   scope       |   allowed
        GrantTypes.AuthorizationCode        |   'public-client'         |   ''                      |   'read'      |   true
        GrantTypes.AuthorizationCode        |   'public-client'         |   ''                      |   'write'     |   true

        GrantTypes.AuthorizationCode        |   'confidential-client'   |   'secret-pass-phrase'    |   'read'      |   true
        GrantTypes.AuthorizationCode        |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   true

        GrantTypes.Implicit                 |   'public-client'         |   ''                      |   'read'      |   true
        GrantTypes.Implicit                 |   'public-client'         |   ''                      |   'write'     |   true

        GrantTypes.Implicit                 |   'confidential-client'   |   'secret-pass-phrase'    |   'read'      |   true
        GrantTypes.Implicit                 |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   true

        GrantTypes.ResourceOwnerCredentials |   'public-client'         |   ''                      |   'read'      |   true
        GrantTypes.ResourceOwnerCredentials |   'public-client'         |   ''                      |   'write'     |   true

        GrantTypes.ResourceOwnerCredentials |   'confidential-client'   |   'secret-pass-phrase'    |   'read'      |   true
        GrantTypes.ResourceOwnerCredentials |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   true

        GrantTypes.ClientCredentials        |   'public-client'         |   ''                      |   'read'      |   true
        GrantTypes.ClientCredentials        |   'public-client'         |   ''                      |   'write'     |   false

        GrantTypes.ClientCredentials        |   'confidential-client'   |   'secret-pass-phrase'    |   'read'      |   true
        GrantTypes.ClientCredentials        |   'confidential-client'   |   'secret-pass-phrase'    |   'trust'     |   false

    }
}
