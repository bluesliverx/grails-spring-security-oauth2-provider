package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.provider.BaseClientDetails
import org.springframework.security.oauth2.provider.ClientDetails

class GormOAuth2Client {

    String clientId
    String clientSecret

    Integer accessTokenValiditySeconds
    Integer refreshTokenValiditySeconds

    static hasMany = [
            authorities: String,
            grantTypes: String,
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
        grantTypes nullable: true

        resourceIds nullable: true
        scopes nullable: true

        redirectUris nullable: true
    }

    static mapping = {
        version false
    }

    ClientDetails toClientDetails() {
        def details = new BaseClientDetails(clientId, csv(resourceIds), csv(scopes), csv(grantTypes), csv(authorities), csv(redirectUris))
        details.clientSecret = clientSecret
        details.accessTokenValiditySeconds  = accessTokenValiditySeconds ?: null
        details.refreshTokenValiditySeconds = refreshTokenValiditySeconds ?: 0
        return details
    }

    private static String csv(Collection collection) {
        collection?.join(',')
    }
}
