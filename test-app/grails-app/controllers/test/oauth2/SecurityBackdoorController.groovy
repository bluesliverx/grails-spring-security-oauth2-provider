package test.oauth2

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.annotation.Secured

@Secured(["permitAll"])
class SecurityBackdoorController {

    def containsGrantedAuthority(String grantedAuthority) {
        def currentAuthorities = SpringSecurityUtils.principalAuthorities
        log.info "Current authorities: $currentAuthorities"

        boolean hasAuthority = currentAuthorities.find { it.authority == grantedAuthority }
        render(status: hasAuthority ? 200 : 404)
    }
}
