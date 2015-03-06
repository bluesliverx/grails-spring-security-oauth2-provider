grails.project.target.level = 1.6
grails.project.source.level = 1.6

grails.project.work.dir = 'target'
grails.project.docs.output.dir = 'docs'
grails.release.scm.enabled = false

grails.project.repos.grailsCentral.username = System.getenv("GRAILS_CENTRAL_USERNAME")
grails.project.repos.grailsCentral.password = System.getenv("GRAILS_CENTRAL_PASSWORD")

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

grails.project.dependency.resolver = 'maven'
grails.project.dependency.resolution = {

	inherits 'global'
	log 'warn'

	repositories {
		grailsCentral()
		mavenLocal()
		mavenCentral()
	}

	dependencies {
		compile 'org.springframework.security.oauth:spring-security-oauth2:2.0.4.RELEASE', {
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

        compile "com.fasterxml.jackson.core:jackson-databind:2.4.1.3"

        test 'org.codehaus.groovy.modules.http-builder:http-builder:0.7.1', {
            export = false
            excludes "commons-logging", "xml-apis", "groovy"
        }

        test 'cglib:cglib-nodep:2.2.2', {
            export = false
        }

        test 'org.objenesis:objenesis:1.4', {
            export = false
        }

        test "org.gebish:geb-spock:0.9.3", {
            export = false
        }

        // Workaround for java.lang.ClassNotFoundException: org.apache.http.conn.HttpClientConnectionManager
        // that is thrown during the initialization of the selenium driver for 2.42.x.
        test "org.apache.httpcomponents:httpclient:4.3.2", {
            export = false
        }

        test "org.seleniumhq.selenium:selenium-chrome-driver:2.42.2", {
            export = false
        }

        test 'com.github.detro.ghostdriver:phantomjsdriver:1.1.0', {
            transitive = false
            export = false
        }
    }

	plugins {
		// Release
		build ":tomcat:7.0.55", ':release:3.0.1', ':rest-client-builder:1.0.3', {
			export = false
		}

		// Testing
		test ':code-coverage:2.0.3-2', {
			export = false
		}
		test ':codenarc:0.21', {
			export = false
		}

        runtime ":hibernate:3.6.10.14", {
            export = false
        }

        test ":geb:0.9.3", {
            export = false
        }

        compile ':spring-security-core:2.0-RC4'
	}
}
