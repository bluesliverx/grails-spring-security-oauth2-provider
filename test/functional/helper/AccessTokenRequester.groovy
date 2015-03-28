package helper

import grails.util.BuildSettings
import groovyx.net.http.HttpResponseDecorator
import groovyx.net.http.RESTClient

class AccessTokenRequester {

    private static RESTClient restClient = new RESTClient()

    private static final BASE_URL = System.getProperty(BuildSettings.FUNCTIONAL_BASE_URL_PROPERTY)
    static final TOKEN_ENDPOINT_URL = BASE_URL + 'oauth/token'

    private static boolean useHttpBasic() {
        System.properties['http.basic'] == 'true'
    }

    static HttpResponseDecorator requestAccessToken(Map requestParams) {
        if (useHttpBasic()) {
            System.out.println("Using HTTP Basic client authentication")

            Map params = requestParams.clone() // Don't mess with the original Map
            String clientId = params.remove('client_id')
            String clientSecret = params.remove('client_secret') ?: ''

            requestAccessTokenWithBasicAuth(params, clientId, clientSecret)

        } else {
            // Default to authentication via request parameters
            restClient.post(uri: TOKEN_ENDPOINT_URL, query: requestParams)
        }
    }

    static String getAccessToken(Map params) {
        def response = requestAccessToken(params)
        return response.data.access_token
    }

    static String getRefreshToken(Map params) {
        def response = requestAccessToken(params)
        return response.data.refresh_token
    }

    static HttpResponseDecorator requestAccessTokenWithBasicAuth(Map params, String clientId, String clientSecret) {
        def basicAuth = "$clientId:$clientSecret".bytes.encodeBase64()
        def headers = clientId ? [Authorization: "Basic $basicAuth"] : [:]
        restClient.post(uri: TOKEN_ENDPOINT_URL, query: params, headers: headers)
    }
}
