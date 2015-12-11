package grails.plugin.springsecurity.oauthprovider

import grails.test.mixin.integration.Integration
import grails.transaction.Rollback
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.approval.Approval
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler
import spock.lang.Specification
import test.oauth2.Client
import test.oauth2.UserApproval

/*
    Port of ApprovalStoreUserApprovalHandlerTests from Spring Security OAuth to
    ensure the GORM backed services work properly with the ApprovalStoreUserApprovalHandler
*/
@Integration
@Rollback
class ApprovalStoreUserApprovalHandlerIntegrationSpec extends Specification {

    ApprovalStoreUserApprovalHandler handler
    Authentication userAuthentication

    Client client

    String clientId
    String username

    @Autowired
    GormApprovalStoreService gormApprovalStoreService

    @Autowired
    ApprovalStoreUserApprovalHandler approvalStoreUserApprovalHandler

    void setup() {
        handler = approvalStoreUserApprovalHandler

        clientId = 'client'
        username = 'user'

        userAuthentication = new UsernamePasswordAuthenticationToken(username, 'N/A',
                AuthorityUtils.commaSeparatedStringToAuthorityList('USER'))
    }

    void setupData() {
        client = new Client(
                clientId: clientId,
                scopes: ['read', 'write'],
                authorizedGrantTypes: ['authorization_code']
        ).save(failOnError: true)
    }

    void "explicitly approved scopes"() {
        given:
        setupData()

        and:
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
        setupData()

        and:
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
        setupData()

        and:
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
        setupData()

        and:
        client.autoApproveScopes = ['read']
        client.save(failOnError: true)

        and:
        def authorizationRequest = new AuthorizationRequest(clientId, ['read'])

        expect:
        handler.checkForPreApproval(authorizationRequest, userAuthentication).isApproved()
    }

    void "auto approved wildcard scopes"() {
        given:
        setupData()

        and:
        client.autoApproveScopes = ['.*']
        client.save(failOnError: true)

        and:
        def authorizationRequest = new AuthorizationRequest(clientId, ['read'])

        expect:
        handler.checkForPreApproval(authorizationRequest, userAuthentication).isApproved()
    }

    void "auto approved all scopes"() {
        given:
        setupData()

        and:
        client.autoApproveScopes = ['true']
        client.save(failOnError: true)

        and:
        def authorizationRequest = new AuthorizationRequest(clientId, ['read'])

        expect:
        handler.checkForPreApproval(authorizationRequest, userAuthentication).isApproved()
    }

    void "expired pre-approved scopes"() {
        given:
        setupData()

        and:
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
