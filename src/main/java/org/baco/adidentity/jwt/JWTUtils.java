package org.baco.adidentity.jwt;

import org.eclipse.microprofile.config.ConfigProvider;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;
import java.util.logging.Logger;

public interface JWTUtils {

    static PrivateKey getPrivateKey() throws IOException, Exception {
        Optional<String> pemEncodedConfig = ConfigProvider.getConfig().getOptionalValue(JWTConfig.PRIVATE_KEY_CONFIG, String.class);
        // Is pem encoded string private key is not present use default resource
        if(pemEncodedConfig.orElse("DEFAULT").equals("DEFAULT")) {
            Logger.getLogger("org.baco.adidentity.jwt").warning("USING DEFAULT PRIVATE KEY INTENDED FOR DEVELOPMENT, " +
                    "THIS IS A SECURITY RISK. YOU SHOULD CONFIGURE PARAMETER security.jwt.privatekey WITH YOUR OWN PRIVATE KEY");
            Optional<String> defaultPemEncodedConfig = ConfigProvider.getConfig().getOptionalValue(JWTConfig.DEFAULT_PRIVATE_KEY_CONFIG, String.class);
            return decodePrivateKey(defaultPemEncodedConfig.get());
        } else {
            String pemEncoded = pemEncodedConfig.get();
            return decodePrivateKey(pemEncoded);
        }
    }

    static PrivateKey decodePrivateKey(final String pemEncoded) throws Exception {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    static byte[] toEncodedBytes(final String pemEncoded) {
        final String normalizedPem = removeBeginEnd(pemEncoded);
        return Base64.getDecoder().decode(normalizedPem);
    }

    static String removeBeginEnd(String pem) {
        pem = pem.replaceAll("-----BEGIN RSA PRIVATE KEY-----", "");
        pem = pem.replaceAll("-----END RSA PRIVATE KEY-----", "");
        pem = pem.replaceAll("-----BEGIN PRIVATE KEY-----", "");
        pem = pem.replaceAll("-----END PRIVATE KEY-----", "");
        pem = pem.replaceAll("\r\n", "");
        pem = pem.replaceAll("\n", "");
        return pem.trim();
    }

}
