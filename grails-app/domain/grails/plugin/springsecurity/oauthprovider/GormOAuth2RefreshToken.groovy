package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken

class GormOAuth2RefreshToken {

    byte[] authentication
    String value

    static constraints = {
        value nullable: false, blank: false, unique: true
        authentication nullable: false, validator: { val, obj -> val.size() > 0 }
    }

    static mapping = {
        version false
    }

    OAuth2RefreshToken toRefreshToken() {
        new DefaultOAuth2RefreshToken(value)
    }
}
