package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2ValidationException
import grails.test.spock.IntegrationSpec
import org.springframework.security.oauth2.provider.approval.Approval
import org.springframework.security.oauth2.provider.approval.ApprovalStore
import spock.lang.Unroll
import test.oauth2.UserApproval

class GormApprovalStoreServiceIntegrationSpec extends IntegrationSpec {

    def gormApprovalStoreService

    String username
    String clientId
    String scope

    Date expiresAt
    Date lastUpdatedAt

    void setup() {
        username = 'user'
        clientId = 'clientId'
        scope = 'read'

        expiresAt = ageDate(new Date(), 7)
        lastUpdatedAt = new Date()
    }

    private Approval createApproval(Map overrides = [:]) {
        def approval = new Approval(username, clientId, scope, expiresAt, Approval.ApprovalStatus.APPROVED, lastUpdatedAt)
        addOverrides(approval, overrides)
        return approval
    }

    private UserApproval createGormApproval(Map overrides = [:]) {
        def approval = new UserApproval(
                username: username,
                clientId: clientId,
                scope: scope,
                expiration: expiresAt,
                lastModified: lastUpdatedAt
        )
        addOverrides(approval, overrides)
        approval.save(failOnError: true)
    }

    private void addOverrides(Object obj, Map overrides) {
        overrides.each { key, value ->
            obj."$key" = value
        }
    }

    private Date ageDate(Date start, int numberOfDays) {
        def calendar = Calendar.instance
        calendar.time = start
        calendar.add(Calendar.DATE, numberOfDays)
        calendar.time
    }

    void "must be an instance of ApprovalStore"() {
        expect:
        gormApprovalStoreService instanceof ApprovalStore
    }

    @Unroll
    void "add new approval that is approved [#approved]"() {
        given:
        def approval = createApproval(status: status)

        when:
        def success = gormApprovalStoreService.addApprovals([approval])

        then:
        success

        and:
        def gormApproval = UserApproval.findByUsername(username)
        gormApproval != null

        and:
        gormApproval.approved == approved
        gormApproval.username == username
        gormApproval.clientId == clientId
        gormApproval.scope == scope
        gormApproval.expiration == expiresAt
        gormApproval.lastModified == lastUpdatedAt

        where:
        approved    |   status
        true        |   null
        true        |   Approval.ApprovalStatus.APPROVED
        false       |   Approval.ApprovalStatus.DENIED
    }

    void "add multiple approvals"() {
        given:
        def approval1 = createApproval(userId: 'user1', clientId: 'client1')
        def approval2 = createApproval(userId: 'user1', clientId: 'client2')
        def approval3 = createApproval(userId: 'user2', clientId: 'client1')

        expect:
        gormApprovalStoreService.addApprovals([approval1, approval2, approval3])

        and:
        UserApproval.findByUsernameAndClientId('user1', 'client1') != null
        UserApproval.findByUsernameAndClientId('user1', 'client2') != null
        UserApproval.findByUsernameAndClientId('user2', 'client1') != null
    }

    @Unroll
    void "update an existing approval and change status to [#newStatus]"() {
        given:
        def approval = createApproval()
        gormApprovalStoreService.addApprovals([approval])

        and:
        def newExpiresAt = ageDate(approval.expiresAt, 4)
        def newLastUpdatedAt = ageDate(approval.lastUpdatedAt, 14)

        assert newExpiresAt != expiresAt
        assert newLastUpdatedAt != lastUpdatedAt

        and:
        approval.status = newStatus
        approval.expiresAt = newExpiresAt
        approval.lastUpdatedAt = newLastUpdatedAt

        when:
        def success = gormApprovalStoreService.addApprovals([approval])

        then:
        success

        and:
        def gormApproval = UserApproval.findByUsername(username)
        gormApproval != null

        and:
        gormApproval.approved == approved
        gormApproval.username == username
        gormApproval.clientId == clientId
        gormApproval.scope == scope
        gormApproval.expiration == newExpiresAt
        gormApproval.lastModified == newLastUpdatedAt

        where:
        approved    |   newStatus
        true        |   null
        true        |   Approval.ApprovalStatus.APPROVED
        false       |   Approval.ApprovalStatus.DENIED
    }

    void "attempt to add invalid approval"() {
        given:
        def approval = createApproval(clientId: null)

        when:
        gormApprovalStoreService.addApprovals([approval])

        then:
        def e = thrown(OAuth2ValidationException)

        e.message.startsWith('Failed to save approval')
        !e.errors.allErrors.empty
    }

    void "get approvals when no approvals exist"() {
        expect:
        gormApprovalStoreService.getApprovals(username, clientId).isEmpty()
    }

    @Unroll
    void "revoke single approval when handleRevocationAsExpiry is [#handleRevocationAsExpiry]"() {
        given:
        def savedFlag = gormApprovalStoreService.handleRevocationAsExpiry
        gormApprovalStoreService.handleRevocationAsExpiry = handleRevocationAsExpiry

        and:
        createGormApproval()

        def approvals = gormApprovalStoreService.getApprovals(username, clientId)
        assert approvals.size() == 1

        when:
        def success = gormApprovalStoreService.revokeApprovals(approvals)

        then:
        success

        and:
        if(handleRevocationAsExpiry) {
            assert UserApproval.findByUsernameAndClientId(username, clientId).expiration <= new Date()
        }
        else {
            assert UserApproval.findByUsernameAndClientId(username, clientId) == null
        }

        cleanup:
        gormApprovalStoreService.handleRevocationAsExpiry = savedFlag

        where:
        handleRevocationAsExpiry << [true, false]
    }

    @Unroll
    void "revoke only approvals specified for different user/client pairs when handleRevocationAsExpiry is [#handleRevocationAsExpiry]"() {
        given:
        def savedFlag = gormApprovalStoreService.handleRevocationAsExpiry
        gormApprovalStoreService.handleRevocationAsExpiry = handleRevocationAsExpiry

        and:
        createGormApproval(username: 'user1', clientId: 'client1', scope: 'read')
        createGormApproval(username: 'user1', clientId: 'client1', scope: 'write')

        createGormApproval(username: 'user1', clientId: 'client2')
        createGormApproval(username: 'user2', clientId: 'client1') // do not revoke

        def approvals =
                gormApprovalStoreService.getApprovals('user1', 'client1') +
                gormApprovalStoreService.getApprovals('user1', 'client2')

        assert approvals.size() == 3

        when:
        def success = gormApprovalStoreService.revokeApprovals(approvals)

        then:
        success

        and:
        if(handleRevocationAsExpiry) {
            assert UserApproval.findByUsernameAndClientIdAndScope('user1', 'client1', 'read').expiration <= new Date()
            assert UserApproval.findByUsernameAndClientIdAndScope('user1', 'client1', 'write').expiration <= new Date()
            assert UserApproval.findByUsernameAndClientId('user1', 'client2').expiration <= new Date()

            assert UserApproval.findByUsernameAndClientId('user2', 'client1').expiration == expiresAt
        }
        else {
            assert UserApproval.findByUsernameAndClientIdAndScope('user1', 'client1', 'read') == null
            assert UserApproval.findByUsernameAndClientIdAndScope('user1', 'client1', 'write') == null
            assert UserApproval.findByUsernameAndClientId('user1', 'client2') == null

            assert UserApproval.findByUsernameAndClientId('user2', 'client1') != null
        }

        cleanup:
        gormApprovalStoreService.handleRevocationAsExpiry = savedFlag

        where:
        handleRevocationAsExpiry << [true, false]
    }


    void "get single approval"() {
        given:
        def gormApproval = createGormApproval()

        when:
        def approvals = gormApprovalStoreService.getApprovals(username, clientId)

        then:
        approvals.size() == 1

        and:
        approvals[0].userId == gormApproval.username
        approvals[0].clientId == gormApproval.clientId
        approvals[0].scope == gormApproval.scope
        approvals[0].approved == gormApproval.approved
        approvals[0].expiresAt == gormApproval.expiration
        approvals[0].lastUpdatedAt == gormApproval.lastModified
    }

    void "get multiple approvals and exclude those not matching the requested approvals"() {
        given:
        def gormApproval1 = createGormApproval(username: 'user1', clientId: 'client1', scope: 'read', approved: true)
        def gormApproval2 = createGormApproval(username: 'user1', clientId: 'client1', scope: 'write', approved: false)

        and:
        createGormApproval(username: 'user1', clientId: 'client2')
        createGormApproval(username: 'user2', clientId: 'client1')

        when:
        def approvals = gormApprovalStoreService.getApprovals('user1', 'client1')

        then:
        approvals.size() == 2

        and:
        def approval1 = approvals.find { it.scope == 'read' }
        def approval2 = approvals.find { it.scope == 'write' }

        and:
        approval1.userId == gormApproval1.username
        approval1.clientId == gormApproval1.clientId
        approval1.scope == gormApproval1.scope
        approval1.approved == gormApproval1.approved
        approval1.expiresAt == gormApproval1.expiration
        approval1.lastUpdatedAt == gormApproval1.lastModified

        and:
        approval2.userId == gormApproval2.username
        approval2.clientId == gormApproval2.clientId
        approval2.scope == gormApproval2.scope
        approval2.approved == gormApproval2.approved
        approval2.expiresAt == gormApproval2.expiration
        approval2.lastUpdatedAt == gormApproval2.lastModified
    }
}
