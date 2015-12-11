package helper

import grails.plugin.springsecurity.oauthprovider.serialization.OAuth2AuthenticationSerializer
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request

class OAuth2AuthenticationFactory {

    OAuth2AuthenticationSerializer oauth2AuthenticationSerializer
    Authentication userAuthentication

    private static final int MAX_SIZE = 1024 * 4

    OAuth2Authentication createLargeOAuth2Authentication() {
        List<GrantedAuthority> authorities = []

        OAuth2Authentication authentication = createOAuth2Authentication(authorities: authorities)
        byte[] serialized = oauth2AuthenticationSerializer.serialize(authentication) as byte[]

        while(serialized.length <= MAX_SIZE) {
            String role = 'authority-' + authorities.size()
            authorities << new SimpleGrantedAuthority(role)

            authentication = createOAuth2Authentication(authorities: authorities)
            serialized = oauth2AuthenticationSerializer.serialize(authentication) as byte[]
        }

        return authentication
    }

    OAuth2Authentication createOAuth2Authentication(Map args = [:]) {
        OAuth2Request request = OAuth2RequestFactory.createOAuth2Request(args)
        return new OAuth2Authentication(request, userAuthentication)
    }
}
