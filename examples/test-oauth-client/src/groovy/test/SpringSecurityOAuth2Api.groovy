package test

import org.scribe.builder.api.DefaultApi20
import org.scribe.exceptions.OAuthException
import org.scribe.extractors.AccessTokenExtractor
import org.scribe.model.OAuthConfig
import org.scribe.model.Token
import org.scribe.utils.OAuthEncoder
import org.scribe.utils.Preconditions

/**
 *
 * @author bsaville
 */
class SpringSecurityOAuth2Api extends DefaultApi20 {
	@Override
	public String getAccessTokenEndpoint() {
		return "http://localhost:8080/test-oauth/oauth/token?grant_type=authorization_code&redirect_uri=http://localhost:8081/test-oauth-client/test/verify";
	}

	@Override
	public String getAuthorizationUrl(OAuthConfig oAuthConfig) {
		return "http://localhost:8080/test-oauth/oauth/authorize?response_type=code&client_id=1&client_secret=secret&redirect_uri=http://localhost:8081/test-oauth-client/test/verify";
	}

	@Override
	public AccessTokenExtractor getAccessTokenExtractor() {
		return new GrailsTokenExtractor();
	}
}

class GrailsTokenExtractor implements AccessTokenExtractor {
	private static final TOKEN_REGEX = ~/"access_token":\s*"([^"]+)"/;
	private static final String EMPTY_SECRET = '';

	/**
	 * {@inheritDoc}
	 */
	public Token extract(String response) {
		Preconditions.checkEmptyString(response, "Response body is incorrect. Can't extract a token from an empty string");

		def matcher = TOKEN_REGEX.matcher(response);
		if (matcher.find()) {
			String token = OAuthEncoder.decode(matcher.group(1));
			return new Token(token, EMPTY_SECRET, response);
		} else {
			throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'", null);
		}
	}
}