grails.project.work.dir = 'target'
grails.project.docs.output.dir = 'target/docs' // for backwards-compatibility, the docs are checked into gh-pages branch

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
		grailsCentral()
		mavenLocal()
		mavenCentral()
	}

	dependencies {
		compile 'org.springframework.security.oauth:spring-security-oauth2:1.0.5.RELEASE', {
			excludes "spring-beans",
			         "spring-core",
			         "spring-context",
			         "spring-aop",
			         "spring-jdbc",
			         "spring-webmvc",
			         "spring-security-core",
			         "spring-security-config",
			         "spring-security-web",
			         "spring-tx",
			         "commons-codec"
		}
	}

	plugins {
		// Release
		build ':release:2.2.1', ':rest-client-builder:1.0.3', {
			export = false
		}

		// Testing
		test ':code-coverage:1.2.4', {
			export = false
		}
		test ':codenarc:0.15', {
			export = false
		}

		compile ':spring-security-core:2.0-RC2'
	}
}
