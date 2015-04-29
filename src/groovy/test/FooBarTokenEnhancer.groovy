package test

import groovy.util.logging.Slf4j
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.TokenEnhancer

@Slf4j
class FooBarTokenEnhancer implements TokenEnhancer {

    @Override
    OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        if(accessToken instanceof DefaultOAuth2AccessToken) {
            (accessToken as DefaultOAuth2AccessToken).additionalInformation = [foo: 'bar']
        }
        return accessToken
    }
}
