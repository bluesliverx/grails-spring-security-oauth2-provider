package test.oauth2

import grails.test.mixin.integration.Integration
import helper.TestEnvironmentCleaner
import spock.lang.Specification

@Integration
abstract class AbstractTokenEndpointFunctionalSpec extends Specification {

    def cleanup() {
        TestEnvironmentCleaner.cleanup()
    }
}
