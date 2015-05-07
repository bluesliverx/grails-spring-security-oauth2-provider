package grails.plugin.springsecurity.oauthprovider

class DefaultOAuth2ScopeSerializer implements OAuth2ScopeSerializer {

    @Override
    Object serialize(Set<String> scopes) {
        return scopes
    }

    @Override
    Set<String> deserialize(Object scopes) {
        if(!(scopes instanceof Set)) {
            throw new IllegalArgumentException("Serialized scopes must be a Set")
        }
        return scopes as Set
    }
}
