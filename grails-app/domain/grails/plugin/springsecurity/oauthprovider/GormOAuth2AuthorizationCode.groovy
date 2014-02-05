package grails.plugin.springsecurity.oauthprovider

class GormOAuth2AuthorizationCode {

    byte[] authentication
    String code

    static constraints = {
        code nullable: false, blank: false, unique: true
        authentication nullable: false, validator: { val, obj -> val.size() > 0 }
    }
}
