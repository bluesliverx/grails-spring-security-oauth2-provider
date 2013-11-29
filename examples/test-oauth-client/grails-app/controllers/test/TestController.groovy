package test

import org.scribe.model.Token
import org.scribe.model.Verifier
import uk.co.desirableobjects.oauth.scribe.OauthService

class TestController {
	OauthService oauthService
	private static final Token EMPTY_TOKEN = new Token('', '')

    def index() {

	}

	def verify() {
		Verifier verifier = new Verifier(params.code)
		Token accessToken = oauthService.getMineAccessToken(EMPTY_TOKEN, verifier)
		render text:oauthService.getMineResource(accessToken, 'http://localhost:8080/test-oauth/book/list').body, contentType:"text/html"
	}
}
