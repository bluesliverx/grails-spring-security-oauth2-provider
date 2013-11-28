package test

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.annotation.Secured
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.WebAttributes

@Secured(["ROLE_ADMIN"])
class SecuredController {
	def index = {
		
	}
}
