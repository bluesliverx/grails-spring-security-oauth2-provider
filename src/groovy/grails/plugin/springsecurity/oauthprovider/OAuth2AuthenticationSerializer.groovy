package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.common.util.SerializationUtils

class OAuth2AuthenticationSerializer {

    byte[] serialize(OAuth2Authentication authentication) {
        SerializationUtils.serialize(authentication)
    }

    OAuth2Authentication deserialize(byte[] authentication) {
        new ByteArrayInputStream(authentication).withObjectInputStream(getClass().classLoader) { ois ->
            ois.readObject() as OAuth2Authentication
        }
    }
}
