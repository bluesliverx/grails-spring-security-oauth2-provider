package grails.plugin.springsecurity.oauthprovider.serialization;

import java.util.Set;

public interface OAuth2ScopeSerializer {

    Object serialize(Set<String> scopes);

    Set<String> deserialize(Object scopes);
}
