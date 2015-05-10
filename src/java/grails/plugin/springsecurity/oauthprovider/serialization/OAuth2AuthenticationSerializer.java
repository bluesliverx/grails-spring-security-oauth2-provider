package grails.plugin.springsecurity.oauthprovider.serialization;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

public interface OAuth2AuthenticationSerializer {

    Object serialize(OAuth2Authentication authentication);

    OAuth2Authentication deserialize(Object authentication);
}
