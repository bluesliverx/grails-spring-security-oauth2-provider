package test.oauth2

import grails.plugin.springsecurity.annotation.Secured

class SecuredWebResourcesController {

    @Secured(["ROLE_CLIENT"])
    def clientRole() {
        render "form client role"
    }

    @Secured(["ROLE_USER"])
    def userRole() {
        render "form user role"
    }
}
