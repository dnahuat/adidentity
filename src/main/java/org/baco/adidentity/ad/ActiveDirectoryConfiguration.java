package org.baco.adidentity.ad;

import io.quarkus.arc.config.ConfigProperties;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Configuration keys for AD server
 */
@ConfigProperties(prefix = "adidentity.adserver")
public interface ActiveDirectoryConfiguration {

    static String DOMAIN_CONFIG = "adidentity.adserver.domain";
    static String DOMAIN_DEFAULT = "addomain";

    static String HOST_CONFIG = "adidentity.adserver.host";
    static String HOST_DEFAULT = "adhost";

    static String PORT_CONFIG = "adidentity.adserver.port";
    static String PORT_DEFAULT = "389";

    static String ORGUNIT_CONFIG = "adidentity.adserver.orgunit";
    static String ORGUNIT_DEFAULT = "Users";

    static String USERNAME_CONFIG = "adidentity.adserver.username";
    static String USERNAME_DEFAULT = "aduser";

    static String PASSWORD_CONFIG = "adidentity.adserver.password";
    static String PASSWORD_DEFAULT = "secret";

    @ConfigProperty(name = "domain", defaultValue = DOMAIN_DEFAULT)
    String getDomain();
    @ConfigProperty(name = "host", defaultValue = HOST_DEFAULT)
    String getHost();
    @ConfigProperty(name = "port", defaultValue = PORT_DEFAULT)
    String getPort();
    @ConfigProperty(name = "orgunit", defaultValue = ORGUNIT_DEFAULT)
    String getOrgunit();
    @ConfigProperty(name = "username", defaultValue = USERNAME_DEFAULT)
    String getUsername();
    @ConfigProperty(name = "password", defaultValue = PASSWORD_DEFAULT)
    String getPassword();
}
