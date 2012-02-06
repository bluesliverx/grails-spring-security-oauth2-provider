import org.springframework.security.oauth2.provider.BaseClientDetails;
import grails.util.Environment;
import test.*

class BootStrap {
	def grailsApplication
	def clientDetailsService
	
	def init = { servletContext ->
		if (Environment.current == Environment.DEVELOPMENT) {
			// Add a test user
			User user = new User(
				username:"admin",
				password:"password",
				enabled:true
			)
			user.save(failOnError:true)
			Role role = new Role(authority:"ROLE_ADMIN")
			role.save(failOnError:true)
			new UserRole(user:user, role:role).save(failOnError:true, flush:true)
			
			// Add client to oauth provider only in dev env
			def client = new BaseClientDetails()
			client.clientId = "clientId"
			client.clientSecret = "clientSecret"
			client.authorizedGrantTypes = ["authorization_code", "refresh_token", "client_credentials", "password", "implicit"]
			clientDetailsService.clientDetailsStore = [
				"clientId":client
			]
		}
	}
	def destroy = {
	}
}
