package helper

class AccessTokenAssert {

    static void assertRequiredAccessTokenData(Map data) {
        assert data.access_token
        assert data.token_type == 'bearer'
        assert (data.expires_in as int) > 0
    }

    static void assertAccessTokenDataContainsRefreshToken(Map data) {
        assert data.refresh_token
        assert data.refresh_token != data.access_token
    }

    static void assertAccessTokenDataDoesNotContainRefreshToken(Map data) {
        assert !data?.refresh_token
    }

    static void assertAccessTokenDataContainsScopes(Map data, List scopes) {
        def scopesAsList = data?.scope?.tokenize()
        assert scopes.size() == (scopesAsList?.size() ?: 0)

        scopes.each {
            assert scopesAsList.contains(it)
        }
    }
}
