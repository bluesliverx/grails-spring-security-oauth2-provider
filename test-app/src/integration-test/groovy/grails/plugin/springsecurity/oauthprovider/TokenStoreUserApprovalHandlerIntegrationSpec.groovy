package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.integration.Integration
import grails.transaction.Rollback
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler
import spock.lang.Specification
import test.oauth2.Client

/*
    Port of TokenStoreUserApprovalHandlerTests from Spring Security OAuth to
    ensure the GORM backed services work properly with the TokenStoreUserApprovalHandler
*/
@Integration
@Rollback
class TokenStoreUserApprovalHandlerIntegrationSpec extends Specification {

    @Autowired
    TokenStoreUserApprovalHandler handler

    Authentication userAuthentication

    String approvalParameter
    String clientId

    def tokenStoreUserApprovalHandler
    def tokenServices
    def oauth2RequestFactory

    void setup() {
        handler = tokenStoreUserApprovalHandler
        approvalParameter = handler.approvalParameter

        userAuthentication = new TestingAuthenticationToken('marissa', null)
        userAuthentication.authenticated = true

        clientId = 'client'
    }

    void setupData() {
        new Client(
                clientId: clientId,
                scopes: ['read', 'write'],
                authorizedGrantTypes: ['authorization_code']
        ).save(failOnError: true)
    }

    void "basic approval"() {
        given:
        def params = [(approvalParameter): 'true']

        def request = new AuthorizationRequest(params, null, null, null, null, null, false, null, null, null)
        request.approved = true

        expect:
        handler.isApproved(request, userAuthentication)
    }

    void "memorized approval"() {
        given:
        setupData()
        def params = [(approvalParameter): 'false', client_id: clientId]

        def request = new AuthorizationRequest(params, null, clientId, null, null, null, false, null, null, null)
        request.approved = false

        def storedOAuth2Request = oauth2RequestFactory.createOAuth2Request(request)
        tokenServices.createAccessToken(new OAuth2Authentication(storedOAuth2Request, userAuthentication))

        when:
        request = handler.checkForPreApproval(request, userAuthentication)

        then:
        handler.isApproved(request, userAuthentication)
    }
}
