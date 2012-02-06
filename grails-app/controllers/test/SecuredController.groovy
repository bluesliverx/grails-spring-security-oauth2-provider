package test

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import grails.plugins.springsecurity.Secured
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.WebAttributes

@Secured(["ROLE_ADMIN"])
class SecuredController {
	def index = {
		
	}
}
