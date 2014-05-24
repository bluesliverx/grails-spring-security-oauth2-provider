class SpringSecurityOauth2ProviderUrlMappings {

    static mappings = {
		"/oauth/authorize"(uri:"/oauth/authorize.dispatch")
		"/oauth/token"(uri:"/oauth/token.dispatch")
	}
}
