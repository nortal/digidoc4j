/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.exceptions.CertificateNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.impl.BDocContainer;
import org.digidoc4j.impl.Certificates;
import org.digidoc4j.impl.DDocContainer;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.signers.PKCS12Signer;
import org.digidoc4j.utils.Helper;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import static junit.framework.Assert.assertEquals;
import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;
import static org.digidoc4j.Signature.Validate.VALIDATE_FULL;
import static org.digidoc4j.utils.DateUtils.isAlmostNow;
import static org.digidoc4j.utils.Helper.deleteFile;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class SignatureTest extends DigiDoc4JTestHelper {

  private PKCS12Signer PKCS12_SIGNER;

  @Before
  public void setUp() throws Exception {
    PKCS12_SIGNER = new PKCS12Signer("testFiles/signout.p12", "test".toCharArray());
  }

  @Test
  public void testGetSigningCertificateForBDoc() throws Exception {
    Container container = Container.open("testFiles/asics_for_testing.bdoc");
    byte[] certificate = container.getSignatures().get(0).getSigningCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.SIGNING_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test
  public void testTimeStampCreationTimeForBDoc() throws ParseException {
    Container container = Container.open("testFiles/test.asice");
    Date timeStampCreationTime = container.getSignature(0).getTimeStampCreationTime();
    SimpleDateFormat dateFormat = new SimpleDateFormat("MMM d yyyy H:m:s", Locale.ENGLISH);
    assertEquals(dateFormat.parse("Nov 17 2014 16:11:46"), timeStampCreationTime);
  }

  @Test (expected = DigiDoc4JException.class)
  public void testTimeStampCreationTimeForDDoc() throws ParseException {
    Container container = Container.create(DDOC);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.getSignature(0).getTimeStampCreationTime();
    container.getSignature(0).getTimeStampCreationTime();
  }

  @Test
  public void testTimeStampCreationTimeForBDocWhereNotOCSP() throws ParseException {
    BDocContainer container = new BDocContainer();
    container.setSignatureProfile(Container.SignatureProfile.B_BES);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);

    assertNull(container.getSignature(0).getTimeStampCreationTime());
  }

  @Test
  public void testGetTimeStampTokenCertificateForBDoc() throws Exception {
    Signature signature = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc").getSignatures().get(0);
    byte[] certificate = signature.getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.TS_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetTimeStampTokenCertificateForBDocNoTimeStampExists() throws Exception {
    Container.open("testFiles/asics_for_testing.bdoc").getSignatures().get(0).getTimeStampTokenCertificate();
  }

  @Test(expected = NotYetImplementedException.class)
  public void testSetCertificateForBDOC() throws Exception {
    BDocContainer bDocContainer = new BDocContainer();
    bDocContainer.addDataFile("testFiles/test.txt", "text/plain");
    Signature bDocSignature = bDocContainer.sign(new PKCS12Signer("testFiles/signout.p12", "test".toCharArray()));
    bDocSignature.setCertificate(new X509Cert("testFiles/signout.pem"));
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetSignerRolesForBDoc_OCSP_Exception() {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    List<Signature> signatures = container.getSignatures();
    signatures.get(0).getOCSPCertificate();
  }

  @Test
  public void testGetSigningTimeForDDOC() {
    testGetSigningTime(DDOC);
  }

  @Test
  public void testGetSigningTimeForBDoc() {
    testGetSigningTime(BDOC);
  }

  private void testGetSigningTime(Container.DocumentType ddoc) {
    Signature signature = getSignature(ddoc);
    assertTrue(isAlmostNow(signature.getSigningTime()));
  }

  @Test
  public void testGetIdForDDOC() {
    Signature signature = getSignature(DDOC);
    assertEquals("S0", signature.getId());
  }

  @Test
  public void testGetIdForBDoc() {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals("id-99E491801522116744419D9357CEFCC5", container.getSignatures().get(0).getId());
  }

  @Test
  public void testGetNonce() {
    Signature signature = getSignature(DDOC);
    assertEquals(null, Base64.encodeBase64String(signature.getOcspNonce())); //todo correct nonce is needed
  }

  @Test
  public void testGetOCSPCertificateForDDoc() throws CertificateEncodingException {
    testGetOCSPCertificate(getSignature(DDOC));
  }

  @Test
  public void testGetOCSPCertificateForBDoc() throws CertificateEncodingException {
    testGetOCSPCertificate(getSignature(BDOC));
  }

  private void testGetOCSPCertificate(Signature signature) throws CertificateEncodingException {
    byte[] encoded = signature.getOCSPCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.OCSP_CERTIFICATE, Base64.encodeBase64String(encoded));
  }

  @Test
  public void testGetSignaturePolicyForDDoc() {
    assertEquals("", getSignature(DDOC).getPolicy());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyForBDoc() throws Exception {
    Signature signature = getSignature(BDOC);
    assertEquals("", signature.getPolicy());
  }

  @Test
  public void testGetProducedAtForDDoc() {
    assertTrue(isAlmostNow(getSignature(DDOC).getProducedAt()));
  }

  @Test
  public void testGetProducedAtForBDoc() throws ParseException {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    Date date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z").parse("2014-07-08 12:51:16 +0000");
    assertEquals(date, container.getSignatures().get(0).getProducedAt());
  }

  @Test
  public void testValidationForDDoc() {
    assertEquals(0, getSignature(DDOC).validate(VALIDATE_FULL).size());
  }

  @Test
  public void testValidationNoParametersForDDoc() {
    assertEquals(0, getSignature(DDOC).validate().size());
  }

  @Test
  public void testValidationForBDocDefaultValidation() throws Exception {
    Container container = Container.open("testFiles/two_signatures.bdoc");
    Signature signature = container.getSignatures().get(0);
    assertEquals(0, signature.validate().size());
    signature = container.getSignatures().get(1);
    assertEquals(0, signature.validate().size());
  }

  @Test
  public void testValidationForBDocDefaultValidationWithFailure() throws Exception {
    Signature signature = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc").getSignatures().get(0);
    assertEquals(1, signature.validate().size());
  }

  @Test
  public void testValidationForBDocDefaultValidationWithOneFailing() throws Exception {
    Container container = Container.open("testFiles/two_signatures_one_invalid.bdoc");
    Signature signature = container.getSignatures().get(0);
    assertEquals(0, signature.validate().size());
    signature = container.getSignatures().get(1);
    assertEquals(1, signature.validate().size());
    ValidationResult validate = container.validate();
    assertEquals(1, validate.getErrors().size());

    assertTrue(validate.getReport().contains("Id=\"S0\" SignatureFormat=\"XAdES_BASELINE_LT\""));
    assertTrue(validate.getReport().contains("Id=\"S1\" SignatureFormat=\"XAdES_BASELINE_LT\""));
  }

  @Test
  public void testValidationWithInvalidDDoc() {
    Signature signature = Container.open("testFiles/changed_digidoc_test.ddoc").getSignatures().get(0);
    assertEquals(4, signature.validate(VALIDATE_FULL).size());
  }

  @Test
  public void testGetSignaturePolicyURIForDDoc() {
    assertNull(getSignature(DDOC).getSignaturePolicyURI());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyURIForBDoc() throws Exception {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals(new URI(""), container.getSignatures().get(0).getSignaturePolicyURI());
  }

  @Test
  public void testGetSignatureMethodDDoc() {
    assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", getSignature(DDOC).getSignatureMethod());
  }

  @Test
  public void testGetSignatureMethodForBDoc() {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256",
        container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void testGetProfileForDDoc() {
    assertEquals(Container.SignatureProfile.LT_TM, getSignature(DDOC).getProfile());
  }

  @Test
  public void testGetProfileForBDoc_TS() throws Exception {
    Container container = Container.open("testFiles/ocsp_cert_is_not_in_tsl.bdoc");
    assertEquals(Container.SignatureProfile.LT, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void testGetProfileForBDoc_None() throws Exception {
    Container container = Container.open("testFiles/asics_for_testing.bdoc");
    assertEquals(Container.SignatureProfile.B_BES, container.getSignatures().get(0).getProfile());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetTimeStampTokenCertificateForDDoc() {
    assertNull(getSignature(DDOC).getTimeStampTokenCertificate());
  }

  private Signature getSignature(Container.DocumentType documentType) {
    Container container = Container.create(documentType);
    container.addDataFile("testFiles/test.txt", "text/plain");

    return container.sign(PKCS12_SIGNER);
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetNonceForBDoc() {
    Container container = Container.open("testFiles/asics_for_testing.bdoc");
    container.getSignatures().get(0).getOcspNonce();
  }

  @Test
  public void testGetSignaturesWhereNoSignaturePresent() throws Exception {
    DDocContainer container = new DDocContainer();
    assertNull(container.getSignatures());
  }

  @Test
  public void testGetSignaturesWhereSignatureDoesNotHaveLastCertificate() throws Exception {
    DDocContainer container = new DDocContainer("testFiles/signature_without_last_certificate.ddoc");
    assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void getSignatureXMLForBDOC() throws Exception {
    Container container = Container.create();
    container.addDataFile("testFiles/test.txt", "text/plain");
    Signature signature = container.sign(PKCS12_SIGNER);

    container.save("getSignatureXMLForBDOC.bdoc");
    String signatureFromContainer = Helper.extractSignature("getSignatureXMLForBDOC.bdoc", 0);


    deleteFile("getSignatureXMLForBDOC.bdoc");

    assertXMLEqual(signatureFromContainer, new String(signature.getRawSignature()));
  }
}
