package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder

import static org.springframework.security.oauth2.common.util.SerializationUtils.deserialize
import static org.springframework.security.oauth2.common.util.SerializationUtils.serialize

class AuthorizationRequestHolderSerializer {

    byte[] serialize(AuthorizationRequestHolder authentication) {
        serialize(authentication)
    }

    AuthorizationRequestHolder deserialize(byte[] authentication) {
        new ByteArrayInputStream(authentication).withObjectInputStream(getClass().classLoader) { ois ->
            ois.readObject() as AuthorizationRequestHolder
        }
    }
}
