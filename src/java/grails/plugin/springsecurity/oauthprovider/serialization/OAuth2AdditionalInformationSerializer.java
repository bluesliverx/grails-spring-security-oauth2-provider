package grails.plugin.springsecurity.oauthprovider.serialization;

import java.util.Map;

public interface OAuth2AdditionalInformationSerializer {

    Object serialize(Map<String, Object> additionalInformation);

    Map<String, Object> deserialize(Object additionalInformation);
}
