package helper

import groovyx.net.http.RESTClient

class TestEnvironmentCleaner {

    private static RESTClient restClient = new RESTClient()

    private static final CLEANUP_URL = FunctionalTestConfig.BASE_URL + 'cleanup'

    static void cleanup() {
        restClient.get(uri: CLEANUP_URL)
    }
}
