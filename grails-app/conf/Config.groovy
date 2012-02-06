// Secure the oauth endpoints
grails.plugins.springsecurity.controllerAnnotations.staticRules = [
	'/oauth/authorize.dispatch':['ROLE_ADMIN'],
]
// Added by the Spring Security Core plugin:
grails.plugins.springsecurity.userLookup.userDomainClassName = 'test.User'
grails.plugins.springsecurity.userLookup.authorityJoinClassName = 'test.UserRole'
grails.plugins.springsecurity.authority.className = 'test.Role'

grails.serverURL = "http://localhost:8080/oauth2"

log4j = {
	debug	'grails.app.bootstrap.BootStrap',
			'grails.app'
	info	'org.hibernate.SQL',
			'org.springframework.security'
	error	'org.codehaus.groovy.grails.web.servlet',	//	controllers
			'org.codehaus.groovy.grails.web.pages', 	//	GSP
			'org.codehaus.groovy.grails.orm.hibernate', // hibernate integration
			'org.codehaus.groovy.grails.web.sitemesh',	//	layouts
			'org.springframework',
			'org.hibernate',
			'org.codehaus.groovy.grails.web.mapping.filter', // URL mapping
			'org.codehaus.groovy.grails.web.mapping', // URL mapping
			'org.codehaus.groovy.grails.plugins', // plugins
			'org.codehaus.groovy.grails.commons' // core / classloading
	warn	'org.mortbay.log'
}