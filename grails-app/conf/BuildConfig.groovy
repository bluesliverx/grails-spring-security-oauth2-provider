grails.work.dir = "target/workdir"
grails.project.class.dir = 'target/classes'
grails.project.test.class.dir = 'target/test-classes'
grails.project.test.reports.dir	= 'target/test-reports'
grails.project.docs.output.dir = 'target/docs' // for backwards-compatibility, the docs are checked into gh-pages branch

grails.release.scm.enabled = false

// Code Narc
codenarc.reports = {
	XmlReport('xml') {
		outputFile = 'target/test-reports/CodeNarcReport.xml'
		title = 'OAuth2 Provider Plugin Report'
	}
	HtmlReport('html') {
		outputFile = 'target/test-reports/CodeNarcReport.html'
		title = 'OAuth2 Provider Plugin Report'
	}
}

grails.project.dependency.resolution = {
	inherits 'global'
	log 'warn'
	repositories {
		grailsPlugins()
		grailsHome()
		grailsCentral()

//		mavenLocal()
		mavenCentral()
	}

	dependencies {
//		compile('org.springframework.security:spring-security-crypto:3.1.4.RELEASE') {
//			excludes 'spring-core', 'commons-logging'
//		}
		compile 'org.springframework.security.oauth:spring-security-oauth2:1.0.4.RELEASE', {
			transitive = false
		}
		compile 'org.springframework.security:spring-security-config:3.0.7.RELEASE', {
			excludes 'spring-core', 'spring-context', 'spring-aop', 'spring-web',
					'aspectjweaver', 'servlet-api', 'commons-logging', 'aopalliance'
		}
	}
	
	plugins {
		// Release
		build (':release:2.0.4') {
			export = false
			excludes 'rest-client-builder'
		}
		build (':rest-client-builder:1.0.2') {
			export = false
		}

		// Testing
		test ':code-coverage:1.2.4', {
			export = false
		}
		test ':codenarc:0.15', {
			export = false
		}
		compile ':spring-security-core:1.2.7.3'
	}
}
