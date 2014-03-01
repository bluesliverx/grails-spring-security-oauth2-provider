package grails.plugin.springsecurity.oauthprovider

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator
import static org.codehaus.groovy.grails.web.servlet.HttpHeaders.*

class OAuth2ExceptionController {

    WebResponseExceptionTranslator webResponseExceptionTranslator

    def clientRegistrationExceptionHandler() {
        renderOAuth2Exception(new BadClientCredentialsException())
    }

    def oAuth2ExceptionHandler() {
        def e = extractOAuth2ExceptionFromRequest()
        renderOAuth2Exception(e)
    }

    private OAuth2Exception extractOAuth2ExceptionFromRequest() {
        ResponseEntity<OAuth2Exception> entity = webResponseExceptionTranslator.translate(request.exception)
        return entity.body
    }

    private void renderOAuth2Exception(OAuth2Exception e) {
        addHeaders(e)
        render(status: e.httpErrorCode, contentType: 'application/json', encoding: 'utf-8') {
            [
                    error: e.OAuth2ErrorCode,
                    error_description: e.message
            ]
        }
    }

    private void addHeaders(OAuth2Exception e) {
        header(CACHE_CONTROL, 'no-store')
        header(PRAGMA, 'no-cache')

        boolean unauthorized = (e.httpErrorCode == HttpStatus.UNAUTHORIZED.value())
        boolean insufficientScope = (e instanceof InsufficientScopeException)

        if(unauthorized || insufficientScope) {
            def challenge = String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, e.summary)
            header(WWW_AUTHENTICATE, challenge)
        }
    }
}
