package helper

class ErrorDescriptions {

    static final String FULL_AUTHENTICATION_REQUIRED = 'Full authentication is required to access this resource'
    static final String BAD_CREDENTIALS = 'Bad credentials'
    static final String BAD_CLIENT_CREDENTIALS = 'Bad client credentials'
    static final String SCOPE_REQUIRED = 'Empty scope (either the client or the user is not allowed the requested scopes)'
    static final String GRANT_TYPE_REQUIRED = 'A client must have at least one authorized grant type.'
    static final String IMPLICIT_GRANT_TYPE_UNSUPPORTED = 'Implicit grant type not supported from token endpoint'

    static String unsupportedGrantType(String grantType) {
        return "Unsupported grant type: $grantType"
    }

    static String unauthorizedGrantType(String grantType) {
        return "Unauthorized grant type: $grantType"
    }

    static String invalidRefreshToken(String refreshToken) {
        return "Invalid refresh token: $refreshToken"
    }

    static String unableToNarrowScope(String scope) {
        return "Unable to narrow the scope of the client authentication to [$scope]."
    }
}
