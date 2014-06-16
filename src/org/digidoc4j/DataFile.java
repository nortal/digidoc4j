package org.digidoc4j;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;

import org.digidoc4j.exceptions.DigiDoc4JException;

/**
 * Data file wrapper providing methods for handling signed files or files to be signed in Container.
 */
public class DataFile {

  private DSSDocument document = null;
  private Digest digest = null;

  /**
   * Creates container.
   *
   * @param path     file name with path
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   */
  public DataFile(String path, String mimeType) {
    try {
      document = new FileDocument(path);
      document.setMimeType(MimeType.fromCode(mimeType));
    } catch (Exception e) {
      throw new DigiDoc4JException(e);
    }
  }

  /**
   * Creates in memory document container.
   *
   * @param data     file content
   * @param fileName file name with path
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   */
  public DataFile(byte[] data, String fileName, String mimeType) {
    document = new InMemoryDocument(data, fileName, MimeType.fromCode(mimeType));
  }

  /**
   * Calculates digest http://www.w3.org/2001/04/xmlenc#sha256 for the data file.
   * If the digest has already been calculated it will return it, otherwise it calculates the digest.
   * <p/>
   *
   * @return calculated digest
   * @throws Exception thrown if the file does not exist or the digest calculation fails.
   */
  public byte[] calculateDigest() throws Exception {
    return calculateDigest(new URL("http://www.w3.org/2001/04/xmlenc#sha256"));
  }

  /**
   * Calculates digest for data file. If digest is already calculated returns it, otherwise calculates the digest.
   * <p>Supported uris for BDoc:</p>
   * <br>http://www.w3.org/2000/09/xmldsig#sha1
   * <br>http://www.w3.org/2001/04/xmldsig-more#sha224
   * <br>http://www.w3.org/2001/04/xmlenc#sha256
   * <br>http://www.w3.org/2001/04/xmldsig-more#sha384
   * <br>http://www.w3.org/2001/04/xmlenc#sha512
   * <p>In case of DDoc files the parameter is ignored and SHA1 hash is always returned</p>
   *
   * @param method method uri for calculating the digest
   * @return calculated digest
   * @throws Exception thrown if the file does not exist or the digest calculation fails.
   */
  public byte[] calculateDigest(URL method) throws Exception {        // TODO exceptions to throw
    if (digest == null) {
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(method.toString());
      digest = new Digest(digestAlgorithm, calculateDigestInternal(digestAlgorithm));
    }
    return digest.getValue();
  }

  protected byte[] calculateDigestInternal(DigestAlgorithm digestAlgorithm) {
    return DSSUtils.digest(digestAlgorithm, document.getBytes());
  }

  /**
   * Returns the data file name.
   *
   * @return filename
   */
  public String getFileName() {
    if (document instanceof InMemoryDocument)
      return document.getName();
    return document.getAbsolutePath();
  }

  /**
   * Returns the data file size.
   *
   * @return file size
   */
  public long getFileSize() {
    return document.getBytes().length;
  }

  /**
   * Returns the file media type.
   *
   * @return media type
   */
  public String getMediaType() {
    return document.getMimeType().getCode();
  }

  /**
   * Saves a copy of the data file as a file to the specified stream.
   *
   * @param out stream where data is written to
   * @throws java.io.IOException is thrown when it's not possible to write to the stream
   */
  public void saveAs(OutputStream out) throws IOException {
    out.write(document.getBytes());
  }

  /**
   * Saves a copy of the data file as a file with the specified file name.
   *
   * @param path full file path where the data file should be saved to. If the file exists it will be overwritten
   * @throws java.io.IOException thrown if part of the path does not exist
   *                             or the path is an existing directory (without file name)
   */
  //TODO exception - method throws DSSException which can be caused by other exceptions
  public void saveAs(String path) throws IOException {
    document.save(path);
  }
}