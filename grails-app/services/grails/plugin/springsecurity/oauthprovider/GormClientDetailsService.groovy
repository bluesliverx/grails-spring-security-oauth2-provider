package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.security.oauth2.provider.BaseClientDetails
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.ClientRegistrationException
import org.springframework.security.oauth2.provider.NoSuchClientException

class GormClientDetailsService implements ClientDetailsService {

    GrailsApplication grailsApplication

    @Override
    ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {

        def (defaultClientConfig, clientLookup) = getClientConfiguration()

        Class Client = getClientClass(clientLookup.className)
        def clientIdPropertyName = clientLookup.clientIdPropertyName

        def client = Client.findWhere((clientIdPropertyName): clientId)
        if(client == null) {
            throw new NoSuchClientException("No client with requested id: $clientId")
        }
        return createClientDetails(client, clientLookup, defaultClientConfig)
    }

    private def getClientConfiguration() {
        def oauthProviderConfig = SpringSecurityUtils.securityConfig.oauthProvider

        def defaultClientConfig = oauthProviderConfig.defaultClientConfig
        def clientLookup = oauthProviderConfig.clientLookup

        return [defaultClientConfig, clientLookup]
    }

    private Class getClientClass(String clientClassName) {
        def clientClass = grailsApplication.getDomainClass(clientClassName)
        if(!clientClass) {
            throw new IllegalArgumentException("The specified client domain class '$clientClassName' is not a domain class")
        }
        return clientClass.clazz
    }

    private ClientDetails createClientDetails(client, clientLookup, defaultClientConfig) {

        // Load configurable property names
        def clientIdPropertyName = clientLookup.clientIdPropertyName
        def clientSecretPropertyName = clientLookup.clientSecretPropertyName
        def accessTokenValiditySecondsPropertyName = clientLookup.accessTokenValiditySecondsPropertyName
        def refreshTokenValiditySecondsPropertyName = clientLookup.refreshTokenValiditySecondsPropertyName
        def authoritiesPropertyName = clientLookup.authoritiesPropertyName
        def authorizedGrantTypesPropertyName = clientLookup.authorizedGrantTypesPropertyName
        def resourceIdsPropertyName = clientLookup.resourceIdsPropertyName
        def scopesPropertyName = clientLookup.scopesPropertyName
        def redirectUrisPropertyName = clientLookup.redirectUrisPropertyName

        // Load client properties or defaults
        def resourceIds = client."$resourceIdsPropertyName" ?: defaultClientConfig.resourceIds
        def scopes = client."$scopesPropertyName" ?: defaultClientConfig.scope
        def authorizedGrantTypes = client."$authorizedGrantTypesPropertyName" ?: defaultClientConfig.authorizedGrantTypes
        def redirectUris = client."$redirectUrisPropertyName" ?: defaultClientConfig.registeredRedirectUri as Set<String>

        def clientId = client."$clientIdPropertyName"
        def authorities = client."$authoritiesPropertyName"

        def details = new BaseClientDetails(clientId, csv(resourceIds), csv(scopes), csv(authorizedGrantTypes), csv(authorities), csv(redirectUris))
        details.clientSecret = client."$clientSecretPropertyName"
        details.accessTokenValiditySeconds  = client."$accessTokenValiditySecondsPropertyName" ?: defaultClientConfig.accessTokenValiditySeconds
        details.refreshTokenValiditySeconds = client."$refreshTokenValiditySecondsPropertyName" ?: defaultClientConfig.refreshTokenValiditySeconds
        return details
    }

    private static String csv(Collection collection) {
        collection?.join(',')
    }
}
