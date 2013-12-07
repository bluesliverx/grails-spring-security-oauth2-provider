package test

import grails.plugin.springsecurity.annotation.Secured

@Secured(["ROLE_ADMIN"])
class SecuredController {
	def index() {}
}
