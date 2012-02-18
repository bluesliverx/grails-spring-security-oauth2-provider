package grails.plugins.springsecurity.oauthprovider

import org.springframework.security.oauth2.provider.InMemoryClientDetailsService
import org.springframework.security.oauth2.provider.BaseClientDetails

import org.apache.log4j.Logger

class SpringSecurityOAuth2ProviderUtility {
	private static Logger log = Logger.getLogger(this)
	
	static registerClients(ConfigObject config, InMemoryClientDetailsService clientDetailsService) {
		// Reset client details
		clientDetailsService.clientDetailsStore = [:]
		
		// Get default configuration
		def defaultConfig = config.oauthProvider.defaultClientConfig
		
		// Iterate through clients
		config.oauthProvider.clients.each { Map clientConfig ->
			if (!clientConfig.clientId) {
				log.error("Could not configure client without valid ID")
				return
			}
			if (!clientConfig.clientSecret) {
				log.error("Could not configure client ${clientConfig.clientId} without valid secret")
				return
			}
			
			// Make sure it's not a duplicate
			if (clientDetailsService.clientDetailsStore[clientConfig.clientId])
				log.warn("Duplicate client ${clientConfig.clientId} exists, it will be overwritten")
				
			// Configure client details
			def client = new BaseClientDetails()
			client.clientId = clientConfig.clientId
			client.clientSecret = clientConfig.clientSecret ?: null
			client.authorizedGrantTypes = clientConfig.authorizedGrantTypes ?: defaultConfig.authorizedGrantTypes
			client.scope = clientConfig.scope ?: defaultConfig.scope
			client.resourceIds = clientConfig.resourceIds ?: defaultConfig.resourceIds
			client.webServerRedirectUri = clientConfig.registeredRedirectUri ?: defaultConfig.registeredRedirectUri
			client.authorities = clientConfig.authorities ?: defaultConfig.authorities
			
			// Add to client details service
			log.debug("Adding client ${client.clientId} to client details service store")
			clientDetailsService.clientDetailsStore[client.clientId] = client
		}
	}
}
