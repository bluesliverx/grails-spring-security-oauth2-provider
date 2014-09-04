package test.oauth2

import grails.plugin.springsecurity.annotation.Secured

/**
 * Exposes a way for functional test apps to remove resources to ensure the
 * current test environment isn't polluted by prior tests.
 */
@Secured(["permitAll"])
class CleanupController {

    def index() {
        log.info "Removing all access tokens"
        removeAll(AccessToken)

        log.info "Removing all refresh tokens"
        removeAll(RefreshToken)

        log.info "Removing all authorization codes"
        removeAll(AuthorizationCode)

        render(status: 200)
    }

    private static void removeAll(clazz) {
        clazz.withTransaction {
            clazz.all.each { it.delete() }
        }
    }
}
