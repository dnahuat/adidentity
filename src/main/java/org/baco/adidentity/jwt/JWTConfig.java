package org.baco.adidentity.jwt;

import io.quarkus.arc.config.ConfigProperties;
import org.baco.adidentity.ad.ActiveDirectoryConfiguration;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;
import java.util.logging.Logger;

@ConfigProperties(prefix = "security.jwt")
public interface JWTConfig {

    static String PRIVATE_KEY_CONFIG = "security.jwt.privatekey";
    static String DEFAULT_PRIVATE_KEY_CONFIG = "security.jwt.defaultprivatekey";
    static String ISSUER_CONFIG = "mp.jwt.verify.issuer";

    @ConfigProperty(name = "signatureid")
    String getSignatureId();

    @ConfigProperty(name = "privatekey", defaultValue = "DEFAULT")
    String getPrivateKey();

    @ConfigProperty(name = "defaultprivatekey")
    String getDefaultPrivatekey();

}
