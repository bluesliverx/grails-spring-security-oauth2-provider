package test.oauth2

import grails.plugin.springsecurity.annotation.Secured

@Secured('permitAll')
class RedirectController {

    def index() {}
}
