package org.digidoc4j.utils;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.digidoc4j.Container;
import org.digidoc4j.impl.BDocContainer;
import org.junit.After;
import org.junit.Test;

import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.SignatureValidationContext;
import eu.europa.ec.markt.dss.validation102853.ocsp.SKOnlineOCSPSource;

/** 
 * This test is testing a "hack" feature that will probably be rolled back later.
 */
public class OcspSkipListTest extends AbstractSigningTests {
    @Test
    public void skippingOcspForTsaCertificates() throws InterruptedException {
        final List<CertificateToken> ocspInvocations = Collections.synchronizedList(new ArrayList<CertificateToken>());
        
        // TODO: We're hard coding a hash of the TSA public key; if the key changes, this test will fail.
        synchronized(SignatureValidationContext.sha256ForTrustedPublicKeysInHex) {
            SignatureValidationContext.sha256ForTrustedPublicKeysInHex.add("2D8B264193FD4C5EE70BD9F920C5A57DCE30DE3586D5CE8EF3EF9A20BBDAE445");
        }
        
        SKOnlineOCSPSource.listener = new SKOnlineOCSPSource.Listener() {
            @Override
            public void onGetOCSPToken(CertificateToken certificateToken, CertificatePool certificatePool) {
                ocspInvocations.add(certificateToken);
            }
        };
        
        sign();
        
        assertEquals(1, ocspInvocations.size());
    }
    
    @After
    public void restoreOcspListener() {
        SKOnlineOCSPSource.listener = null;
    }

    protected BDocContainer sign() {
        BDocContainer container = (BDocContainer) Container.create(createDigiDoc4JConfiguration());
        container.addDataFile(new ByteArrayInputStream("file contents".getBytes()), "file.txt", "application/octet-stream");
        byte[] hashToSign = prepareSigning(container, CertificatesForTests.SIGN_CERT, createSignatureParameters());
        byte[] signatureValue = signWithRsa(CertificatesForTests.PRIVATE_KEY_FOR_SIGN_CERT, hashToSign);
        container.signRaw(signatureValue);
        return container;
    }
}
