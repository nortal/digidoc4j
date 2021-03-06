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

import org.digidoc4j.exceptions.DigiDoc4JException;

import java.util.List;

/**
 * Validation result information.
 *
 * For BDOC the ValidationResult contains only information for the first signature of each signature XML file
 */
public interface ValidationResult {
  /**
   * Return a list of errors.
   * DDOC returns all validation results as errors.
   *
   * @return list of errors
   */
  List<DigiDoc4JException> getErrors();

  /**
   * Return a list of warnings.
   * DDOC always returns an empty list.
   *
   * @return list of warnings
   */
  List<DigiDoc4JException> getWarnings();

  /**
   * Are there any validation errors.
   *
   * @return value indicating if any errors exist
   */
  boolean hasErrors();

  /**
   * Are there any validation warnings.
   * DDOC always returns false.
   *
   * @return value indicating if any warnings exist
   */
  boolean hasWarnings();

  /**
   * @return true when document is valid
   */
  boolean isValid();

  /**
   * Get validation report.
   *
   * @return report
   */
  String getReport();

  /**
   * Get list container related errors.
   *
   * DDOC returns a list of errors encountered when validating meta data
   * BDOC returns a list of errors encountered when opening the container
   *
   * @return List of exceptions
   */
  List<DigiDoc4JException> getContainerErrors();
}
