package test.oauth2

import grails.plugin.springsecurity.annotation.Secured

class SecuredOAuth2ResourcesController {

    @Secured(["#oauth2.clientHasRole('ROLE_CLIENT')"])
    def clientRoleExpression() {
        render "client role expression"
    }

    @Secured(["ROLE_CLIENT"])
    def clientRole() {
        render "client role"
    }

    @Secured(["#oauth2.clientHasAnyRole('ROLE_CLIENT', 'ROLE_TRUSTED_CLIENT')"])
    def clientHasAnyRole() {
        render "client has any role"
    }

    @Secured(["#oauth2.isClient()"])
    def client() {
        render "is client"
    }

    @Secured(["#oauth2.isUser()"])
    def user() {
        render "is user"
    }

    @Secured(["#oauth2.denyOAuthClient()"])
    def denyClient() {
        render "no client can see"
    }

    @Secured(["permitAll"])
    def anyone() {
        render "anyone can see"
    }

    def nobody() {
        render "nobody can see"
    }

    @Secured(["#oauth2.clientHasRole('ROLE_TRUSTED_CLIENT') and #oauth2.isClient() and #oauth2.hasScope('trust')"])
    def trustedClient() {
        render "trusted client"
    }

    @Secured(["hasRole('ROLE_USER') and #oauth2.isUser() and #oauth2.hasScope('trust')"])
    def trustedUser() {
        render "trusted user"
    }

    @Secured(["hasRole('ROLE_USER') or #oauth2.hasScope('read')"])
    def userRoleOrReadScope() {
        render "user role or read scope"
    }
}
