<?php
// $Id$

/**
 * @file
 * Library functions for FOAF+SSL.
 */

include_once(dirname(__FILE__) . "/arc/ARC2.php");

/**
 * Get all the RDF resources matching a set of (predicate, object) conditions.
 *
 * @param $rdf_index
 *   The simple-indexed RDF graph returned by ARC_Parser::getSimpleIndex().
 * @param $conditions
 *   A set of (predicate, object) conditions.
 * @return
 *   An array of subject identifiers.
 */
function rdf_get_resources(array $rdf_index, array $conditions) {
  $output = array();
  foreach ($rdf_index as $subject => $resource) {
    $match = TRUE;
    foreach ($conditions as $predicate => $object) {
      $match &= isset($resource[$predicate]) && in_array($object, $resource[$predicate]);
    }
    if ($match) {
      $output[] = $subject;
    }
  }
  return $output;
}

/**
 * Verify that a person has a certificate matching the presented one.
 *
 * @param $person_uri
 *   A person identifier.
 * @param $persented_modulus
 *   The modulus (in uppercase normalized hex form) of the certificate
 *   presented by the user.
 * @param $presented_exponent
 *   The exponent (in uppercase normalized hex form) of the certificate
 *   presented by the user.
 * @return
 *   TRUE if the person has a certificate matching the presented certificate,
 *   or FALSE.
 */
function foaf_ssl_match_user($person_uri, $presented_modulus, $presented_exponent) {
  $parser = ARC2::getRDFParser();
  $parser->parse($person_uri);

  $rdf_index = $parser->getSimpleIndex();

  // Required namespaces.
  $rdf = 'http://www.w3.org/1999/02/22-rdf-syntax-ns';
  $rsa = 'http://www.w3.org/ns/auth/rsa';
  $cert = 'http://www.w3.org/ns/auth/cert';

  // First, get a list of certificates matching the person.
  $matched_certificates = rdf_get_resources($rdf_index, array(
    $rdf . '#type' => $rsa . '#RSAPublicKey',
    $cert . '#identity' => $person_uri,
  ));

  // Iterate over the certicates to find a matching modulus, public exponent.
  foreach ($matched_certificates as $certificate_subject) {
    if (!isset($rdf_index[$certificate_subject])) {
      // The certificate is not in the graph.
      continue;
    }

    $certificate = $rdf_index[$certificate_subject];
    $modulus = NULL;
    $public_exponent = NULL;

    // Iterate over the modules to find a candidate.
    if (isset($certificate[$rsa . '#modulus'])) {
      foreach ($certificate[$rsa . '#modulus'] as $modulus_subject) {
        if ($modulus = _foaf_cert_get_key_value($rdf_index[$modulus_subject])) {
          break;
        }
      }
    }

    // Iterate over the public exponents to find a candidate.
    if (isset($certificate[$rsa . '#public_exponent'])) {
      foreach ($certificate[$rsa . '#public_exponent'] as $exponent_subject) {
        if ($public_exponent = _foaf_cert_get_key_value($rdf_index[$exponent_subject])) {
          break;
        }
      }
    }

    if (isset($modulus) && isset($public_exponent)) {
      // Try to match that certificate to what was presented by the user.
      if ($modulus == $presented_modulus && $public_exponent == $presented_exponent) {
        // Yay!
        return TRUE;
      }
    }
  }
  return FALSE;
}

/**
 * Normalize a hex value.
 */
function _foaf_normalize_hex($hex) {
  return strtoupper(preg_replace('/[^a-zA-Z0-9]/', '', $hex));
}

/**
 * Get a key value from a cert value.
 */
function _foaf_cert_get_key_value($candidate) {
  $cert = 'http://www.w3.org/ns/auth/cert';
  $value = NULL;
  if (isset($candidate[$cert . '#hex'])) {
    $value = _foaf_normalize_hex($candidate[$cert . '#hex'][0]);
  }
  else if (isset($candidate[$cert . '#decimal'])) {
    $value = strtoupper(dechex($candidate[$cert . '#decimal'][0]));
  }
  return $value;
}

/**
 * Fetch the Public hex from the information returned by mod_ssl.
 *
 * TODO: remove the dependency on command line openssl.
 */
function _foaf_get_public_key() {
	if ($_SERVER['SSL_CLIENT_CERT']) {
		$pub_key = openssl_pkey_get_public($_SERVER['SSL_CLIENT_CERT']);
		$key_data = openssl_pkey_get_details($pub_key);
	
		$key_len   = strlen($key_data['key']);
		$begin_len = strlen('-----BEGIN PUBLIC KEY----- ');
		$end_len   = strlen(' -----END PUBLIC KEY----- ');

		$rsa_cert = substr($key_data['key'], $begin_len, $key_len - $begin_len - $end_len);

		$rsa_cert_struct = `echo "$rsa_cert" | openssl asn1parse -inform PEM -i`;

		$rsa_cert_fields = split("\n", $rsa_cert_struct);
		$rsakey_offset   = split(":",  $rsa_cert_fields[4]);

		$rsa_key = `echo "$rsa_cert" | openssl asn1parse -inform PEM -i -strparse $rsakey_offset[0]`;

		$rsa_keys = split("\n", $rsa_key);
		$modulus  = split(":", $rsa_keys[1]);
		$exponent = split(":", $rsa_keys[2]);

		return array(
		  'modulus' => $modulus[3],
		  'exponent' => $exponent[3],
		);
	}
}

/**
 * Fetches the subjectAltName of the presented client certificate.
 */
function _foaf_get_subjectaltname() {
	if ($_SERVER['SSL_CLIENT_CERT']) {
		$cert = openssl_x509_parse($_SERVER['SSL_CLIENT_CERT']);
		if ($cert['extensions']['subjectAltName']) {
			$extensions = split("[,]", $cert['extensions']['subjectAltName']);

			foreach ($extensions as $extension) {
				if ($extension) {
					$value = split(":", $extension, 2);
					$output[trim($value[0])] = trim($value[1]);
				}
			}

			return $output;
		}
	}
}

function foaf_try_authentication() {
  $presented_key = _foaf_get_public_key();
  if (empty($presented_key)) {
    return array(
      'error' => 'No client certificate presented.',
    );
  }

  $subject = _foaf_get_subjectaltname();
  if (!isset($subject['URI'])) {
    return array(
      'error' => 'No valid identity found in the presented client certificate.',
    );
  }

  $foaf_uri = $subject['URI'];

  if (foaf_ssl_match_user($foaf_uri, $presented_key['modulus'], $presented_key['exponent'])) {
    return array(
      'authenticated' => TRUE,
      'foaf_uri' => $foaf_uri,
    );
  }
  else {
    return array(
      'error' => 'Presented certificate not found in the FOAF file.',
    );
  }
}
