<?php
// $Id$

/**
 * Administration functions for the FOAF-SSL module.
 */

function foafssl_admin_settings() {
  $form['foafssl_https_base_url'] = array(
    '#type' => 'textfield',
    '#title' => t('HTTPS Base URL'),
    '#description' => t('The HTTPS Base URL of this website (without a / suffix).'),
    '#default_value' => foafssl_https_base_url(),
  );
  return system_settings_form($form);
}
