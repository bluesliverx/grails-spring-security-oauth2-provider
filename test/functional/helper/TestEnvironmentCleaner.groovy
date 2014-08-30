package helper

import grails.util.BuildSettings
import groovyx.net.http.RESTClient

class TestEnvironmentCleaner {

    private static RESTClient restClient = new RESTClient()

    private static final BASE_URL = System.getProperty(BuildSettings.FUNCTIONAL_BASE_URL_PROPERTY)
    private static final CLEANUP_URL = BASE_URL + 'cleanup'

    static void cleanup() {
        restClient.get(uri: CLEANUP_URL)
    }
}
