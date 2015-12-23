package org.openqa.selenium.browserlaunchers;

import org.openqa.selenium.Capabilities;
import org.openqa.selenium.Proxy;

/**
 * Provides a workaround for deprecated methods.
 *
 * See: https://github.com/detro/ghostdriver/pull/399
 */
public class Proxies {

    public static Proxy extractProxy(Capabilities capabilities) {
        return Proxy.extractFrom(capabilities);
    }
}

