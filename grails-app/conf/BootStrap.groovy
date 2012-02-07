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
		}
	}
	def destroy = {
	}
}
