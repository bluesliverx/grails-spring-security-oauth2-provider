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

        test 'org.codehaus.groovy.modules.http-builder:http-builder:0.7.1', {
            export = false
            excludes "commons-logging", "xml-apis", "groovy"
        }

        test "org.spockframework:spock-grails-support:0.7-groovy-2.0", {
            export = false
        }

        test 'cglib:cglib-nodep:2.2.2', {
            export = false
        }

        test 'org.objenesis:objenesis:1.4', {
            export = false
        }

        test "org.gebish:geb-spock:0.9.2", {
            export = false
        }

        test "org.seleniumhq.selenium:selenium-chrome-driver:2.41.0", {
            export = false
        }

        test 'com.github.detro.ghostdriver:phantomjsdriver:1.1.0', {
            transitive = false
            export = false
        }
    }

	plugins {
		// Release
		build ":tomcat:$grailsVersion", ':release:2.2.1', ':rest-client-builder:2.0.1', {
			export = false
		}

		// Testing
		test ':code-coverage:1.2.4', {
			export = false
		}
		test ':codenarc:0.15', {
			export = false
		}

        test(":spock:0.7") {
            exclude "spock-grails-support"
            export = false
        }

        runtime ":hibernate:$grailsVersion", {
            export = false
        }

        test ":geb:0.9.2", {
            export = false
        }

        compile ':spring-security-core:2.0-RC2'
	}
}
