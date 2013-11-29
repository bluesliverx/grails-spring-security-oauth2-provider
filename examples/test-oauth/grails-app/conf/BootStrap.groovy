import test.oauth.Role
import test.oauth.User
import test.oauth.UserRole

class BootStrap {

    def init = { servletContext ->
		Role role = new Role(authority: "ROLE_ADMIN").save(flush:true)
		User user = new User(
				username:"bob",
				password:"pass",
				enabled:true,
				accountExpired:false,
				accountLocked:false,
				passwordExpired:false
		).save(flush:true)
		UserRole.create(user, role, true)
    }
    def destroy = {
    }
}
