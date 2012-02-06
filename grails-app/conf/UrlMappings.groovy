class UrlMappings {

	static mappings = {
		"/$controller/$action?/$id?"{
			constraints {
				// apply constraints here
			}
		}

		"/"(view:"/index")
		"500"(view:'/error')
		
		// OAuth2 Provider endpoints
		"/oauth/confirm.dispatch"(controller:"oauth", action:"confirm")
		"/oauth/authorize"(uri:"/oauth/authorize.dispatch")
		"/oauth/token"(uri:"/oauth/token.dispatch")
	}
}
