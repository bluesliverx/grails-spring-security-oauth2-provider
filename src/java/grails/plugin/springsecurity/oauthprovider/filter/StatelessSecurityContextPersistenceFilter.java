package grails.plugin.springsecurity.oauthprovider.filter;

import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

public class StatelessSecurityContextPersistenceFilter extends SecurityContextPersistenceFilter {

    public StatelessSecurityContextPersistenceFilter() {
        super(new NullSecurityContextRepository());
    }
}