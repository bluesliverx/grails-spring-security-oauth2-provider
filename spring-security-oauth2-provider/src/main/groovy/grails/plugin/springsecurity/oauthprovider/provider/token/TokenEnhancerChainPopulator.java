package grails.plugin.springsecurity.oauthprovider.provider.token;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class TokenEnhancerChainPopulator implements ApplicationListener<ContextRefreshedEvent> {

    private boolean registerTokenEnhancers;

    private static final String TOKEN_ENHANCER_CHAIN_BEAN_NAME = "tokenEnhancerChain";

    public void setRegisterTokenEnhancers(boolean registerTokenEnhancers) {
        this.registerTokenEnhancers = registerTokenEnhancers;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        ApplicationContext ctx = event.getApplicationContext();

        Map<String, TokenEnhancer> availableEnhancers = ctx.getBeansOfType(TokenEnhancer.class);
        availableEnhancers.remove(TOKEN_ENHANCER_CHAIN_BEAN_NAME);

        if (registerTokenEnhancers && !availableEnhancers.isEmpty()) {
            TokenEnhancerChain tokenEnhancerChain = (TokenEnhancerChain) ctx.getBean(TOKEN_ENHANCER_CHAIN_BEAN_NAME);

            List<TokenEnhancer> enhancers = new ArrayList<>(availableEnhancers.values());
            tokenEnhancerChain.setTokenEnhancers(enhancers);
        }
    }
}
