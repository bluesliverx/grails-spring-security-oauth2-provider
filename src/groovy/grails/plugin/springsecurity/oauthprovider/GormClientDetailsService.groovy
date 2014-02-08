package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.ClientRegistrationException
import org.springframework.security.oauth2.provider.NoSuchClientException
import org.springframework.transaction.annotation.Transactional

@Transactional
class GormClientDetailsService implements ClientDetailsService {

    @Override
    ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        def client = GormOAuth2Client.findByClientId(clientId)
        if(client == null) {
            throw new NoSuchClientException("No client with requested id: $clientId")
        }
        return client.toClientDetails()
    }
}
