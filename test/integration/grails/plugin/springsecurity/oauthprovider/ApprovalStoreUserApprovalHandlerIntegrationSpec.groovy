package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.test.spock.IntegrationSpec
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.approval.Approval
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler
import test.oauth2.Client
import test.oauth2.UserApproval

/*
    Port of ApprovalStoreUserApprovalHandlerTests from Spring Security OAuth to
    ensure the GORM backed services work properly with the ApprovalStoreUserApprovalHandler
*/
class ApprovalStoreUserApprovalHandlerIntegrationSpec extends IntegrationSpec {

    ApprovalStoreUserApprovalHandler handler
    Authentication userAuthentication

    Client client

    String clientId
    String username

    def gormApprovalStoreService
    def gormClientDetailsService
    def oauth2RequestFactory

    void setup() {
        def conf = SpringSecurityUtils.securityConfig

        handler = new ApprovalStoreUserApprovalHandler(
                clientDetailsService: gormClientDetailsService,
                approvalStore: gormApprovalStoreService,
                requestFactory: oauth2RequestFactory,
                approvalExpiryInSeconds: conf.oauthProvider.approval.approvalValiditySeconds,
                scopePrefix: conf.oauthProvider.approval.scopePrefix
        )

        clientId = 'client'
        username = 'user'

        client = new Client(
                clientId: clientId,
                scopes: ['read', 'write'],
                authorizedGrantTypes: ['authorization_code']
        ).save(failOnError: true)

        userAuthentication = new UsernamePasswordAuthenticationToken(username, 'N/A',
                AuthorityUtils.commaSeparatedStringToAuthorityList('USER'))
    }

    void "explicitly approved scopes"() {
        given:
        def authorizationRequest = new AuthorizationRequest(clientId, ['read'])
        authorizationRequest.approvalParameters = ['scope.read': 'approved']

        when:
        def result = handler.updateAfterApproval(authorizationRequest, userAuthentication)

        then:
        handler.isApproved(authorizationRequest, userAuthentication)
        gormApprovalStoreService.getApprovals(username, clientId).size() == 1

        and:
        result.scope.size() == 1
        result.isApproved()
    }

    void "implicitly denied scope"() {
        given:
        def authorizationRequest = new AuthorizationRequest(clientId, ['read', 'write'])
        authorizationRequest.approvalParameters = ['scope.read': 'approved']

        when:
        def result = handler.updateAfterApproval(authorizationRequest, userAuthentication)

        then:
        handler.isApproved(authorizationRequest, userAuthentication)

        and:
        def approvals = gormApprovalStoreService.getApprovals(username, clientId)
        approvals.size() == 2

        and:
        approvals.find { it.userId == username && it.clientId == clientId &&
                it.scope == 'read' && it.status == Approval.ApprovalStatus.APPROVED } != null

        approvals.find { it.userId == username && it.clientId == clientId &&
                it.scope == 'write' && it.status == Approval.ApprovalStatus.DENIED } != null

        and:
        result.scope.size() == 1
    }

    void "explicitly pre-approved scopes"() {
        given:
        new UserApproval(
                username: username,
                clientId: clientId,
                scope: 'read',
                approved: true,
                lastModified: new Date(),
                expiration: new Date(System.currentTimeMillis() + 10000)
        ).save(failOnError: true)

        and:
        def authorizationRequest = new AuthorizationRequest(clientId, ['read'])

        expect:
        handler.checkForPreApproval(authorizationRequest, userAuthentication).isApproved()
    }

    void "auto approved scopes"() {
        given:
        client.autoApproveScopes = ['read']
        client.save(failOnError: true)

        and:
        def authorizationRequest = new AuthorizationRequest(clientId, ['read'])

        expect:
        handler.checkForPreApproval(authorizationRequest, userAuthentication).isApproved()
    }

    void "auto approved wildcard scopes"() {
        given:
        client.autoApproveScopes = ['.*']
        client.save(failOnError: true)

        and:
        def authorizationRequest = new AuthorizationRequest(clientId, ['read'])

        expect:
        handler.checkForPreApproval(authorizationRequest, userAuthentication).isApproved()
    }

    void "auto approved all scopes"() {
        given:
        client.autoApproveScopes = ['true']
        client.save(failOnError: true)

        and:
        def authorizationRequest = new AuthorizationRequest(clientId, ['read'])

        expect:
        handler.checkForPreApproval(authorizationRequest, userAuthentication).isApproved()
    }

    void "expired pre-approved scopes"() {
        given:
        new UserApproval(
                username: username,
                clientId: clientId,
                scope: 'read',
                approved: true,
                lastModified: new Date(),
                expiration: new Date(System.currentTimeMillis() - 10000)
        ).save(failOnError: true)

        and:
        def authorizationRequest = new AuthorizationRequest(clientId, ['read'])

        expect:
        !handler.checkForPreApproval(authorizationRequest, userAuthentication).isApproved()
    }
}
