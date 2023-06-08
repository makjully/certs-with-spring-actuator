package ru.digitalhabits.certswithspringactuator.contributor;

import lombok.val;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

@Component
public class CertificatesContributor implements InfoContributor {
    @Value("${certs.resource.name}")
    private String certsResourceName;

    @Value("${certs.password}")
    private String certsPassword;

    @Override
    public void contribute(Info.Builder builder) {
        val certs = new HashMap<>();
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(certsResourceName)) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

            keyStore.load(is, certsPassword.toCharArray());
            keyStore.aliases().asIterator().forEachRemaining(alias -> {
                try {
                    Certificate certificate = keyStore.getCertificate(alias);
                    if (certificate instanceof X509Certificate) {
                        long validityPeriod = ((X509Certificate) certificate).getNotAfter().getTime()
                                - Date.from(Instant.now()).getTime();
                        long validityPeriodInDays = TimeUnit.MILLISECONDS.toDays(validityPeriod);
                        String periodInfo = validityPeriodInDays > 0
                                ? String.format("%d days left", validityPeriodInDays)
                                : String.format("expired %d days ago", Math.abs(validityPeriodInDays));
                        certs.put(alias, periodInfo);
                    }
                } catch (KeyStoreException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }

        builder.withDetail("certificates_info", certs);
    }
}
