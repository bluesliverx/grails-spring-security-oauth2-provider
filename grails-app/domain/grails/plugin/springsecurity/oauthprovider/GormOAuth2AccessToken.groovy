package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2AccessToken

class GormOAuth2AccessToken {

    String value
    String tokenType

    Date expiration
    Date dateCreated

    byte[] authentication

    static hasOne = [refreshToken: GormOAuth2RefreshToken]
    static hasMany = [scope: String]

    static constraints = {
        value blank: false, unique: true
        tokenType blank: false
        expiration nullable: true
        scope nullable: false
    }

    static mapping = {
        version false
    }

    OAuth2AccessToken toAccessToken() {
        def token = new DefaultOAuth2AccessToken(value)
        token.refreshToken = refreshToken ? refreshToken.toRefreshToken() : null
        token.tokenType = tokenType
        token.expiration = expiration
        token.scope = scope
        return token
    }
}
