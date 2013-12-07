import grails.util.Environment
import test.*

class BootStrap {
	def init = { servletContext ->
		if (Environment.isDevelopmentMode()) {
			// Add a test user
			User user = new User(
				username:"admin",
				password:"password"
			).save(failOnError:true)
			Role role = new Role(authority:"ROLE_ADMIN").save(failOnError:true)
			UserRole.create user, role, true
		}
	}
}
