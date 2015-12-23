package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AdditionalInformationSerializer
import grails.core.GrailsApplication
import org.springframework.security.oauth2.provider.client.BaseClientDetails
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.ClientRegistrationException
import org.springframework.security.oauth2.provider.NoSuchClientException

class GormClientDetailsService implements ClientDetailsService {

    GrailsApplication grailsApplication
    OAuth2AdditionalInformationSerializer clientAdditionalInformationSerializer

    @Override
    ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {

        def (defaultClientConfig, clientLookup) = getClientConfiguration()

        Class<?> Client = getClientClass(clientLookup.className)
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
        def clientClass = clientClassName ? grailsApplication.getDomainClass(clientClassName) : null
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
        def autoApproveScopesPropertyName = clientLookup.autoApproveScopesPropertyName
        def redirectUrisPropertyName = clientLookup.redirectUrisPropertyName
        def additionalInformationPropertyName = clientLookup.additionalInformationPropertyName

        // Load client properties or defaults
        def resourceIds = getPropertyOrDefault(client, resourceIdsPropertyName, defaultClientConfig.resourceIds) as Collection<String>
        def scopes = getPropertyOrDefault(client, scopesPropertyName, defaultClientConfig.scope) as Collection<String>
        def authorizedGrantTypes = getPropertyOrDefault(client, authorizedGrantTypesPropertyName, defaultClientConfig.authorizedGrantTypes) as Collection<String>
        def redirectUris = getPropertyOrDefault(client, redirectUrisPropertyName, defaultClientConfig.registeredRedirectUri) as Set<String>

        def clientId = client."$clientIdPropertyName"
        def authorities = getPropertyOrDefault(client, authoritiesPropertyName, defaultClientConfig.authorities) as Collection<String>

        def details = new BaseClientDetails(clientId, csv(resourceIds), csv(scopes), csv(authorizedGrantTypes), csv(authorities), csv(redirectUris))
        details.clientSecret = client."$clientSecretPropertyName"
        details.autoApproveScopes = getPropertyOrDefault(client, autoApproveScopesPropertyName, defaultClientConfig.autoApproveScopes) as Set<String>
        details.accessTokenValiditySeconds  = getPropertyOrDefault(client, accessTokenValiditySecondsPropertyName, defaultClientConfig.accessTokenValiditySeconds) as Integer
        details.refreshTokenValiditySeconds = getPropertyOrDefault(client, refreshTokenValiditySecondsPropertyName, defaultClientConfig.refreshTokenValiditySeconds) as Integer
        details.additionalInformation = getAdditionalInformationOrDefault(client, additionalInformationPropertyName, defaultClientConfig.additionalInformation)
        correctAuthorizedGrantTypes(details, authorizedGrantTypes)
        return details
    }

    private Object getPropertyOrDefault(client, propertyName, defaultProperty) {
        return client."$propertyName" != null ? client."$propertyName" : defaultProperty
    }

    private Map<String, Object> getAdditionalInformationOrDefault(client, propertyName, defaultProperty) {
        Map<String, Object> additionalInformation = defaultProperty

        if(client."$propertyName" != null) {
            additionalInformation = clientAdditionalInformationSerializer.deserialize(client."$propertyName")
        }

        return additionalInformation
    }

    /*
        The constructor for BaseClientDetails defaults the authorized grant types to authorization_code
        and refresh_token. We want the developer to have final say on what grant types a client should have.
        Thus we need to ensure that the ClientDetails we return only contain the authorized grant types that
        either the client or the default config allows.
      */
    private void correctAuthorizedGrantTypes(BaseClientDetails clientDetails, Collection<String> authorizedGrantTypes) {
        clientDetails.authorizedGrantTypes = authorizedGrantTypes
    }

    private static String csv(Collection collection) {
        collection?.join(',')
    }
}
