package grails.plugin.springsecurity.oauthprovider.exceptions;

public abstract class WrappedEndpointException extends RuntimeException {

    public WrappedEndpointException(String message, Throwable cause) {
        super(message, cause);
    }
}