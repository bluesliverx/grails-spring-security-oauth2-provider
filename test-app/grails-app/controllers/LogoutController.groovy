

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.annotation.Secured

// Source: Spring Security Core plugin
@Secured('permitAll')
class LogoutController {

    static allowedMethods = [logout: 'POST']

    def index() {}

    def logout() {
        redirect uri: SpringSecurityUtils.securityConfig.logout.filterProcessesUrl // '/j_spring_security_logout'
    }
}