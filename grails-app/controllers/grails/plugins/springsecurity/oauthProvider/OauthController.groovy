package grails.plugins.springsecurity.oauthProvider

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import grails.plugins.springsecurity.Secured

class OauthController {
	def verificationCodeFilter
	def clientDetailsService
	
	/**
	 * Show the confirm page
	 */
	@Secured(["IS_AUTHENTICATED_REMEMBERED"])
	def confirm = {
		def config = SpringSecurityUtils.securityConfig
		def clientAuth = verificationCodeFilter.authenticationCache.getAuthentication(request, response)
		
		String postUrl = "${request.contextPath}${config.oauthProvider.user.authUrl}"
		[postUrl: postUrl, approvalParameter: config.oauthProvider.user.approvalParameter,
			approvalParameterValue: config.oauthProvider.user.approvalParameterValue,
			client:clientDetailsService.loadClientByClientId(clientAuth.getClientId())]
	}
}
