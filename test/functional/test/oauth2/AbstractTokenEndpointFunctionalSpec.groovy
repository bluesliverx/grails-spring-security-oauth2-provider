package test.oauth2

import helper.TestEnvironmentCleaner
import spock.lang.Specification

abstract class AbstractTokenEndpointFunctionalSpec extends Specification {

    def cleanup() {
        TestEnvironmentCleaner.cleanup()
    }
}
