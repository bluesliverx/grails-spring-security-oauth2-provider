package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken

class GormOAuth2RefreshToken {

    String value
    Date expiration

    static belongsTo = [accessToken: GormOAuth2AccessToken]

    static constraints = {
        value blank: false, unique: true
    }

    static mapping = {
        version false
    }

    ExpiringOAuth2RefreshToken toRefreshToken() {
        new DefaultExpiringOAuth2RefreshToken(value, expiration)
    }
}
