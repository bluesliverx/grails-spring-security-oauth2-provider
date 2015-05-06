package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauthprovider.exceptions.OAuth2ValidationException
import org.springframework.security.oauth2.provider.approval.Approval
import org.springframework.security.oauth2.provider.approval.ApprovalStore

import static org.springframework.security.oauth2.provider.approval.Approval.ApprovalStatus.*

class GormApprovalStoreService implements ApprovalStore {

    def grailsApplication

    boolean handleRevocationAsExpiry

    @Override
    boolean addApprovals(Collection<Approval> approvals) {
        def (approvalLookup, GormApproval) = getApprovalLookupAndClass()

        approvals.each { approval ->

            def usernamePropertyName = approvalLookup.usernamePropertyName
            def clientIdPropertyName = approvalLookup.clientIdPropertyName
            def scopePropertyName = approvalLookup.scopePropertyName
            def approvedPropertyName = approvalLookup.approvedPropertyName
            def expirationPropertyName = approvalLookup.expirationPropertyName
            def lastModifiedPropertyName = approvalLookup.lastModifiedPropertyName

            def gormApproval = GormApproval.findWhere(
                    (usernamePropertyName): approval.userId,
                    (clientIdPropertyName): approval.clientId,
                    (scopePropertyName): approval.scope
            )

            if(gormApproval) {
                gormApproval."$approvedPropertyName" = isApproved(approval)
                gormApproval."$expirationPropertyName" = approval.expiresAt
                gormApproval."$lastModifiedPropertyName" = approval.lastUpdatedAt
                gormApproval.save()
            }
            else {
                def ctorArgs = [
                        (usernamePropertyName): approval.userId,
                        (clientIdPropertyName): approval.clientId,
                        (scopePropertyName): approval.scope,
                        (approvedPropertyName): isApproved(approval),
                        (expirationPropertyName): approval.expiresAt,
                        (lastModifiedPropertyName): approval.lastUpdatedAt
                ]

                gormApproval = GormApproval.newInstance(ctorArgs)
                if(!gormApproval.save()) {
                    throw new OAuth2ValidationException("Failed to save approval", gormApproval.errors)
                }
            }
        }
        return true
    }

    private boolean isApproved(Approval approval) {
        if(approval?.status == DENIED) {
            return false
        }
        return true
    }

    @Override
    boolean revokeApprovals(Collection<Approval> approvals) {
        def (approvalLookup, GormApproval) = getApprovalLookupAndClass()

        def usernamePropertyName = approvalLookup.usernamePropertyName
        def clientIdPropertyName = approvalLookup.clientIdPropertyName
        def scopePropertyName = approvalLookup.scopePropertyName
        def expirationPropertyName = approvalLookup.expirationPropertyName

        approvals.each { approval ->
            def gormApproval = GormApproval.findWhere(
                    (usernamePropertyName): approval.userId,
                    (clientIdPropertyName): approval.clientId,
                    (scopePropertyName): approval.scope
            )

            if(handleRevocationAsExpiry) {
                gormApproval."$expirationPropertyName" = new Date()
                gormApproval.save()
            }
            else {
                gormApproval.delete()
            }
        }

        return true
    }

    @Override
    Collection<Approval> getApprovals(String userId, String clientId) {
        def (approvalLookup, GormApproval) = getApprovalLookupAndClass()

        def usernamePropertyName = approvalLookup.usernamePropertyName
        def clientIdPropertyName = approvalLookup.clientIdPropertyName
        def scopePropertyName = approvalLookup.scopePropertyName
        def approvedPropertyName = approvalLookup.approvedPropertyName
        def expirationPropertyName = approvalLookup.expirationPropertyName
        def lastModifiedPropertyName = approvalLookup.lastModifiedPropertyName

        def gormApprovals = GormApproval.findAllWhere(
                (usernamePropertyName): userId,
                (clientIdPropertyName): clientId
        )

        gormApprovals.collect { gormApproval ->
            new Approval(
                    gormApproval."$usernamePropertyName" as String,
                    gormApproval."$clientIdPropertyName" as String,
                    gormApproval."$scopePropertyName" as String,
                    gormApproval."$expirationPropertyName" as Date,
                    gormApproval."$approvedPropertyName" ? APPROVED : DENIED,
                    gormApproval."$lastModifiedPropertyName" as Date
            )
        }
    }

    private def getApprovalLookupAndClass() {
        def approvalLookup = SpringSecurityUtils.securityConfig.oauthProvider.approvalLookup
        Class GormApproval = getApprovalClass(approvalLookup.className)
        [approvalLookup, GormApproval]
    }

    private Class getApprovalClass(String approvalClassName) {
        def approvalClass = approvalClassName ? grailsApplication.getDomainClass(approvalClassName) : null
        if(!approvalClass) {
            throw new IllegalArgumentException("The specified approval domain class '$approvalClassName' is not a domain class")
        }
        return approvalClass.clazz
    }
}
