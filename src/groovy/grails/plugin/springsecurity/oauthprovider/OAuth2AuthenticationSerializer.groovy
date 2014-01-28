package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.provider.OAuth2Authentication
import static org.springframework.security.oauth2.common.util.SerializationUtils.*

class OAuth2AuthenticationSerializer {

    byte[] serialize(OAuth2Authentication authentication) {
        serialize(authentication)
    }

    OAuth2Authentication deserialize(byte[] authentication) {
        deserialize(authentication)
    }
}
