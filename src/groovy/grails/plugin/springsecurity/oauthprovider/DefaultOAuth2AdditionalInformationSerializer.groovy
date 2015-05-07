package grails.plugin.springsecurity.oauthprovider

class DefaultOAuth2AdditionalInformationSerializer implements OAuth2AdditionalInformationSerializer {

    @Override
    Object serialize(Map<String, Object> additionalInformation) {
        return additionalInformation
    }

    @Override
    Map<String, Object> deserialize(Object additionalInformation) {
        if(!(additionalInformation instanceof Map)) {
            throw new IllegalArgumentException("Serialized additional information must be a Map")
        }
        return additionalInformation as Map
    }
}
