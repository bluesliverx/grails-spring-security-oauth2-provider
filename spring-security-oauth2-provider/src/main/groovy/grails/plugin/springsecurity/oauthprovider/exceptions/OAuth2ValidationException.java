package grails.plugin.springsecurity.oauthprovider.exceptions;

import grails.validation.ValidationException;
import org.springframework.validation.Errors;

public class OAuth2ValidationException extends ValidationException {

    public OAuth2ValidationException(String msg, Errors e) {
        super(msg, e);
    }
}
