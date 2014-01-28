package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2AccessToken

class GormOAuth2AccessToken {

    byte[] authentication

    String username
    String clientId

    String value
    String tokenType

    Date expiration

    static hasOne = [refreshToken: String]
    static hasMany = [scope: String]

    static constraints = {
        username nullable: true
        clientId blank: false
        value blank: false, unique: true
        tokenType blank: false
        expiration nullable: true
        scope nullable: false
        refreshToken nullable: true
    }

    static mapping = {
        version false
    }

    OAuth2AccessToken toAccessToken() {
        def token = new DefaultOAuth2AccessToken(value)
        token.refreshToken = refreshToken ? GormOAuth2RefreshToken.findByValue(refreshToken)?.toRefreshToken() : null
        token.tokenType = tokenType
        token.expiration = expiration
        token.scope = scope
        return token
    }
}
