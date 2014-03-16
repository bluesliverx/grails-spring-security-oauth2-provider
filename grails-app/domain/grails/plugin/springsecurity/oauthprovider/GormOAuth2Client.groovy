package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import org.springframework.security.oauth2.provider.BaseClientDetails
import org.springframework.security.oauth2.provider.ClientDetails

class GormOAuth2Client {

    String clientId
    String clientSecret

    Integer accessTokenValiditySeconds
    Integer refreshTokenValiditySeconds

    static hasMany = [
            authorities: String,
            authorizedGrantTypes: String,
            resourceIds: String,
            scopes: String,
            redirectUris: String
    ]

    static constraints = {
        clientId blank: false, unique: true
        clientSecret nullable: true

        accessTokenValiditySeconds nullable: true
        refreshTokenValiditySeconds nullable: true

        authorities nullable: true
        authorizedGrantTypes nullable: true

        resourceIds nullable: true
        scopes nullable: true

        redirectUris nullable: true
    }

    static mapping = {
        version false
    }

    ClientDetails toClientDetails() {

        def defaultClientConfig = SpringSecurityUtils.securityConfig.oauthProvider.defaultClientConfig

        def resourceIds = this.resourceIds ?: defaultClientConfig.resourceIds
        def scopes = this.scopes ?: defaultClientConfig.scope
        def authorizedGrantTypes = this.authorizedGrantTypes ?: defaultClientConfig.authorizedGrantTypes
        def redirectUris = this.redirectUris ?: defaultClientConfig.registeredRedirectUri as Set<String>

        def details = new BaseClientDetails(clientId, csv(resourceIds), csv(scopes), csv(authorizedGrantTypes), csv(authorities), csv(redirectUris))
        details.clientSecret = clientSecret
        details.accessTokenValiditySeconds  = accessTokenValiditySeconds ?: defaultClientConfig.accessTokenValiditySeconds
        details.refreshTokenValiditySeconds = refreshTokenValiditySeconds ?: defaultClientConfig.refreshTokenValiditySeconds
        return details
    }

    private static String csv(Collection collection) {
        collection?.join(',')
    }
}
