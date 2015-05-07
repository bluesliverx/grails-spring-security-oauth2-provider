package grails.plugin.springsecurity.oauthprovider

interface OAuth2ScopeSerializer {

    Object serialize(Set<String> scopes)

    Set<String> deserialize(Object scopes)
}
