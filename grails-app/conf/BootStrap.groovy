import org.springframework.security.oauth2.provider.BaseClientDetails;
import grails.util.Environment;

class BootStrap {
	def grailsApplication
	def clientDetailsService
	
	def init = { servletContext ->
		if (Environment.current == Environment.DEVELOPMENT) {
			// Add client to oauth provider only in dev env
			def client = new BaseClientDetails()
			client.clientId = "clientId"
			client.clientSecret = "clientSecret"
			client.authorizedGrantTypes = ["authorization_code", "refresh_token", "client_credentials"]
			clientDetailsService.clientDetailsStore = [
				"clientId":client
			]
		}
	}
	def destroy = {
	}
}
