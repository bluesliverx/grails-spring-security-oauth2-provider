package helper

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.provider.OAuth2Request

class OAuth2RequestFactory {

    static OAuth2Request createOAuth2Request(Map args) {
        Map<String, String> parameters = args?.parameters ?: [:]

        String clientId = args?.clientId ?: 'clientId'
        Collection<? extends GrantedAuthority> authorities = args?.authorities

        boolean approved = args?.approved ?: true
        Collection<String> scope = args?.scope as Set<String>

        Set<String> resourceIds = args?.resourceIds
        String redirectUri = args?.redirectUri

        Set<String> responseTypes = args?.responseTypes
        Map<String, Serializable> extensionProperties = args?.extensionProperties

        return new OAuth2Request(parameters, clientId, authorities, approved, scope,
                resourceIds, redirectUri, responseTypes, extensionProperties)
    }
}
