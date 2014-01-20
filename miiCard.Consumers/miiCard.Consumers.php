<?php

/**
 * @file
 * Classes for making OAuth signed requests to the miiCard API.
 */

namespace miiCard\Consumers\Consumers;

use miiCard\Consumers\Model;

/* Specifies whether miiCard's SSL certificate should be verified before
   connections to it are allowed. */
define("MIICARD_VERIFY_SSL_DETAILS", TRUE);

/**
 * @package MiiCardConsumers
 */

// Include OAuth library only if it hasn't already been defined (as for some
// packages like Drupal this'll be a modular dependency)

require_once 'oauth/OAuth.php';

require_once 'miiCard.Model.php';

/**
 * Houses the URLs of the OAuth endpoint and Claims API endpoint.
 *
 * @package MiiCardConsumers
 */
class MiiCardServiceUrls {
  /** URL of the OAuth authorisation endpoint. */
  const OAUTH_ENDPOINT = "https://sts.miicard.com/auth/oauth.ashx";

  /** URL of the Claims API v1 JSON endpoint. */
  const CLAIMS_SVC = "https://sts.miicard.com/api/v1/Claims.svc/json";

  /** URL of the Financial API v1 JSON endpoint. */
  const FINANCIAL_SVC = "https://sts.miicard.com/api/v1/Financial.svc/json";

  /** URL of the Directory API v1 JSON endpoint. */
  const DIRECTORY_SVC = "https://sts.miicard.com/api/v1/Members";

  /**
   * Calculates the URL of a Claims API method.
   *
   * @deprecated Use getClaimsMethodUrl or getFinancialMethodUrl instead.
   *
   * @param string $method
   *   The name of the API method to be invoked.
   */
  public static function getMethodUrl($method) {
    return MiiCardServiceUrls::CLAIMS_SVC . "/" . $method;
  }

  /**
   * Calculates the URL of a Claims API method.
   *
   * @param string $method
   *   The name of the API method to be invoked.
   */
  public static function getClaimsMethodUrl($method) {
    return MiiCardServiceUrls::CLAIMS_SVC . "/" . $method;
  }

  /**
   * Calculates the URL of a Financial API method.
   *
   * @param string $method
   *   The name of the API method to be invoked.
   */
  public static function getFinancialMethodUrl($method) {
    return MiiCardServiceUrls::FINANCIAL_SVC . "/" . $method;
  }

  /**
   * Calculates the URL of a Directory API search request.
   *
   * @param string $criterion
   *   The field on which the search is taking place, like 'email' or 'phone'.
   * @param string $value
   *   The search parameter value, like 'test@example.com'.
   * @param bool $hashed
   *   Specifies that the value has already been SHA1 hashed. Default false.
   */
  public static function getDirectoryServiceQueryUrl($criterion, $value, $hashed = FALSE) {
    $to_return = MiiCardServiceUrls::DIRECTORY_SVC . "?" . $criterion . "=" . $value;
    if ($hashed) {
      $to_return .= "&hashed=true";
    }

    return $to_return;
  }
}

/**
 * Base class for classes that make OAuth 1.0a-signed HTTP requests
 *
 * @abstract
 * @package MiiCardConsumers
 */
abstract class OAuthSignedRequestMaker {
  /**
   * The OAuth consumer key.
   */
  protected $consumerKey;
  /**
   * The OAuth consumer secret.
   */
  protected $consumerSecret;
  /**
   * The OAuth access token, if known.
   */
  protected $accessToken;
  /**
   * The OAuth access token secret, if known.
   */
  protected $accessTokenSecret;

  /**
   * Initialises a new OAuthSignedRequestMaker with specified key and secret.
   *
   * A consumer key and secret are mandatory - without them an
   * InvalidArgumentException is thrown. The caller may supply an access token
   * and secret if they are known, or omit them if they intend to make requests
   * that aren't signed by an access token and secret (for example, as would be
   * the case during an initial OAuth exchange).
   *
   * @param string $consumer_key
   *   The OAuth consumer key obtained by request from miiCard.
   * @param string $consumer_secret
   *   The OAuth consumer secret obtained by request from miiCard.
   * @param string $access_token
   *   The OAuth access token obtained by performing an OAuth exchange.
   * @param string $access_token_secret
   *   The OAuth access token secret obtained by performing an OAuth exchange.
   */
  public function __construct($consumer_key, $consumer_secret, $access_token = NULL, $access_token_secret = NULL) {
    if (!isset($consumer_key)) {
      throw new \InvalidArgumentException("consumerKey cannot be NULL");
    }
    elseif (!isset($consumer_secret)) {
      throw new \InvalidArgumentException("consumerSecret cannot be NULL");
    }

    $this->consumerKey = $consumer_key;
    $this->consumerSecret = $consumer_secret;
    $this->accessToken = $access_token;
    $this->accessTokenSecret = $access_token_secret;
  }

  /**
   * Gets the OAuth consumer key.
   */
  public function getConsumerKey() {
    return $this->consumerKey;
  }

  /**
   * Gets the OAuth consumer secret.
   */
  public function getConsumerSecret() {
    return $this->consumerSecret;
  }

  /**
   * Gets the OAuth access token, or NULL if not set.
   */
  public function getAccessToken() {
    if (isset($this->accessToken)) {
      return $this->accessToken;
    }
    else {
      return NULL;
    }
  }

  /**
   * Gets the OAuth access token secret, or NULL if not set.
   */
  public function getAccessTokenSecret() {
    if (isset($this->accessTokenSecret)) {
      return $this->accessTokenSecret;
    }
    else {
      return NULL;
    }
  }

  /**
   * Makes an OAuth-signed HTTP POST request.
   *
   * Makes signed requests both during the initial OAuth exchange (where OAuth
   * parameters are sent form-encoded as part of the body of the request, with
   * $raw_post_body = FALSE) and afterwards when accessing the API (when JSON-
   * encoded parameters are sent raw in the body of the request).
   *
   * @param string $url
   *   The URL to be requested.
   * @param mixed $params
   *   An array of parameters to be sent with the request as a post
   *   body (if $raw_post_body = FALSE), or a string containing the raw post
   *   body to be sent (if $raw_post_body = TRUE).
   * @param array $headers
   *   Additional HTTP headers to be sent with the request.
   * @param bool $raw_post_body
   *   If TRUE, $params is interpreted as pre-parsed content to be dropped into
   *   the body of the request as-is. If FALSE, the default, $params is
   *   interpreted as an array of key-value pairs to be form-encoded and sent in
   *   the body of the request.
   */
  protected function makeSignedRequest($url, $params, $headers = array(), $raw_post_body = FALSE) {
    $consumer_token = new \OAuthToken($this->consumerKey, $this->consumerSecret);
    $access_token = NULL;

    if ($this->getAccessToken() != NULL && $this->getAccessTokenSecret() != NULL) {
      $access_token = new \OAuthToken($this->getAccessToken(), $this->getAccessTokenSecret());
    }

    if ($raw_post_body) {
      $request = \OAuthRequest::from_consumer_and_token($consumer_token, $access_token, 'POST', $url, NULL);
    }
    else {
      $request = \OAuthRequest::from_consumer_and_token($consumer_token, $access_token, 'POST', $url, $params);
    }

    $request->sign_request(new \OAuthSignatureMethod_HMAC_SHA1(), $consumer_token, $access_token);

    if ($raw_post_body) {
      array_push($headers, $request->to_header());
    }

    if ($raw_post_body) {
      return $this->makeHttpRequest($request->get_normalized_http_url(), $params, $headers, $raw_post_body);
    }
    else {
      return $this->makeHttpRequest($request->get_normalized_http_url(), $request->get_parameters(), $headers, $raw_post_body);
    }
  }

  /**
   * Makes an HTTP Post request, returning the response.
   *
   * @param string $url
   *   The URL to be requested.
   * @param mixed $params
   *   An array of parameters to be sent with the request as a post body (if
   *   $raw_post_body = FALSE), or a string containing the raw post body to be
   *   sent (if $raw_post_body = TRUE).
   * @param array $headers
   *   Additional HTTP headers to be sent with the request.
   * @param bool $raw_post_body
   *   If TRUE, $params is interpreted as pre-parsed content to be dropped into
   *   the body of the request as-is. If FALSE, the default, $params is
   *   interpreted as an array of key-value pairs to be form-encoded and sent in
   *   the body of the request.
   */
  protected function makeHttpRequest($url, $params, $headers = array(), $raw_post_body = FALSE) {
    if (!$raw_post_body) {
      $data = '';
      if (isset($params) && is_array($params) && count($params) > 0) {
        $data = http_build_query($params);
      }
    }

    $uri = @parse_url($url);
    $path = isset($uri['path']) ? $uri['path'] : '/';

    if (isset($uri['query'])) {
      $path .= '?' . $uri['query'];
    }

    $start = microtime(TRUE);
    $port = isset($uri['port']) ? $uri['port'] : 443;
    $socket = 'ssl://' . $uri['host'] . ':' . $port;
    $headers += array(
      'Accept:',
      'Host: ' . $uri['host'] . ($port != 443 ? ':' . $port : ''),
      'User-Agent: miiCard PHP',
    );

    $curl_options = array(
      CURLOPT_URL => $url,
      CURLOPT_CONNECTTIMEOUT => 90,
      CURLOPT_TIMEOUT => 90,
      CURLOPT_FOLLOWLOCATION => TRUE,
      CURLOPT_RETURNTRANSFER => TRUE,
      CURLOPT_SSL_VERIFYHOST => FALSE,
      CURLOPT_SSL_VERIFYPEER => MIICARD_VERIFY_SSL_DETAILS ? 2 : 0,
      CURLOPT_CAINFO => dirname(__FILE__) . "/certs/sts.miicard.com.pem",
      CURLOPT_HTTPHEADER => $headers,
      CURLOPT_FORBID_REUSE => TRUE,
      CURLOPT_FRESH_CONNECT => TRUE,
    );

    if ($raw_post_body) {
      $curl_options[CURLOPT_POSTFIELDS] = $params;
    }
    else {
      $curl_options[CURLOPT_POSTFIELDS] = $data;
    }

    $ch = curl_init();
    curl_setopt_array($ch, $curl_options);
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    return $response;
  }
}

/**
 * Base class for exceptions raised by the library.
 *
 * @package MiiCardConsumers
 */
class MiiCardException extends \Exception {}

/**
 * Base class for wrappers around an OAuth-protected API.
 *
 * @abstract
 * @package MiiCardConsumers
 */
abstract class MiiCardOAuthServiceBase extends OAuthSignedRequestMaker {
  /**
   * Initialises a new MiiCardOAuthServiceBase with specified OAuth credentials.
   *
   * @param string $consumer_key
   *   The OAuth consumer key.
   * @param string $consumer_secret
   *   The OAuth consumer secret.
   * @param string $access_token
   *   The OAuth access token.
   * @param string $access_token_secret
   *   The OAuth access token secret.
   */
  public function __construct($consumer_key, $consumer_secret, $access_token, $access_token_secret) {
    if (!isset($access_token)) {
      throw new \InvalidArgumentException("accessToken cannot be NULL");
    }
    elseif (!isset($access_token_secret)) {
      throw new \InvalidArgumentException("accessTokenSecret cannot be NULL");
    }

    parent::__construct($consumer_key, $consumer_secret, $access_token, $access_token_secret);
  }

  /**
   * Gets the URL of an API method
   *
   * @param string $method_name
   *   The name of the API method to call.
   **/
  abstract protected function getMethodUrl($method_name);

  /**
   * Makes an OAuth signed request to the specified API method.
   *
   * @param string $method_name
   *   The name of the Claims API method to invoke.
   * @param string $post_data
   *   JSON string of parameter data required by the API method, if any.
   * @param Callable $payload_processor
   *   Callable to be invoked to process the payload of the response, if any.
   * @param bool $wrapped_response
   *   Specifies whether the response from the API is wrapped in a
   *   MiiApiResponse object (TRUE), or is a raw stream (FALSE).
   * @param bool $array_type_payload
   *   Specifies that the payload of the response is an array-type - examples
   *   would be the GetIdentitySnapshotDetails call which returns an array of
   *   IdentitySnapshotDetails objects.
   */
  protected function makeRequest($method_name, $post_data, $payload_processor, $wrapped_response, $array_type_payload = FALSE) {
    $response = $this->makeSignedRequest($this->getMethodUrl($method_name), $post_data, array(0 => "Content-Type: application/json"), TRUE);
    if ($response != NULL) {
      if ($wrapped_response) {
        $response = json_decode($response, TRUE);
        return Model\MiiApiResponse::FromHash($response, $payload_processor, $array_type_payload);
      }
      elseif ($payload_processor != NULL) {
        return call_user_func($payload_processor, $response);
      }
      else {
        return $response;
      }
    }
    else {
      throw new MiiCardException("An empty response was received from the server");
    }
  }
}

/**
 * Wrapper around the miiCard Claims API v1.
 *
 * This class wraps the miiCard Claims API v1, exposing the same methods as PHP
 * functions and return types as PHP objects rather than raw JSON.
 *
 * @package MiiCardConsumers
 */
class MiiCardOAuthClaimsService extends MiiCardOAuthServiceBase {
  /**
   * Initialises an MiiCardOAuthClaimsService with specified OAuth credentials.
   *
   * If any constructor parameters are omitted, an InvalidArgumentException
   * shall be thrown.
   *
   * @param string $consumer_key
   *   The OAuth consumer key.
   * @param string $consumer_secret
   *   The OAuth consumer secret.
   * @param string $access_token
   *   The OAuth access token.
   * @param string $access_token_secret
   *   The OAuth access token secret.
   */
  public function __construct($consumer_key, $consumer_secret, $access_token, $access_token_secret) {
    parent::__construct($consumer_key, $consumer_secret, $access_token, $access_token_secret);
  }

  /**
  * Gets the URL of a Claims API method
  *
  * @param string $method_name
  *   The name of the API method to call.
  **/
  protected function getMethodUrl($method_name) {
    return MiiCardServiceUrls::getClaimsMethodUrl($method_name);
  }

  /**
   * Gets the claims that the miiCard member has shared with your application.
   */
  public function getClaims() {
    return $this->makeRequest('GetClaims', NULL, 'miiCard\Consumers\Model\MiiUserProfile::FromHash', TRUE);
  }

  /**
   * Gets whether the miiCard member owns a particular social media account.
   *
   * The social media account is identified by the specified ID and type,
   * and getting this information is dependent on their having shared details of
   * that account with your application.
   *
   * @param string $social_account_id
   *   The ID of the user on the social network in question as supplied by that
   *   social network - see the miiCard Developers site API documentation for
   *   more details.
   * @param string $social_account_type
   *   The network on which thr miiCard member may have an account - see the
   *   miiCard Developers site API documentation for more details.
   */
  public function isSocialAccountAssured($social_account_id, $social_account_type) {
    $request_array = array();
    $request_array['socialAccountId'] = $social_account_id;
    $request_array['socialAccountType'] = $social_account_type;

    return $this->makeRequest('IsSocialAccountAssured', json_encode($request_array), NULL, TRUE);
  }

  /**
   * Gets whether the miiCard member's identity has been assured by miiCard.
   */
  public function isUserAssured() {
    return $this->makeRequest('IsUserAssured', NULL, NULL, TRUE);
  }

  /**
   * Gets an image representation of the miiCard member's identity status.
   *
   * @param string $type
   *   One of 'banner', 'badge-small' or 'badge' that determines the size and
   *   content of the assurance image.
   */
  public function assuranceImage($type) {
    $request_array = array();
    $request_array['type'] = $type;

    return $this->makeRequest('AssuranceImage', json_encode($request_array), NULL, FALSE);
  }

  /**
   * Gets an card-image representation of the miiCard member's identity status.
   *
   * @param string $snapshot_id
   *   If using the transactional model, generates an image using data stored
   *   in the snapshot specified by this ID.
   * @param boolean $show_email_address
   *   If true, the miiCard member's email address is shown on the card.
   * @param boolean $show_phone_number
   *   If true, the miiCard member's phone number is shown on the card. This
   *   defaults to false to protect member privacy.
   * @param string $format
   *   The (optional) format of the image. If not specified, defaults to 'card'.
   *   Can be in the set {card, signature}.
   */
  public function getCardImage($snapshot_id = NULL, $show_email_address = FALSE, $show_phone_number = FALSE, $format = NULL) {
    $request_array = array();
    $request_array['SnapshotId'] = $snapshot_id;
    $request_array['ShowEmailAddress'] = $show_email_address;
    $request_array['ShowPhoneNumber'] = $show_phone_number;
    $request_array['Format'] = $format;

    return $this->makeRequest('GetCardImage', json_encode($request_array), NULL, FALSE);
  }

  /**
   * Gets details of snapshots matching an ID.
   *
   * If no snapshot ID is supplied, details about all snapshots taken by your
   * application for the user are returned.
   *
   * @param string $snapshot_id
   *   The unique identifier of the snapshot for which details should be
   *   retrieved, or NULL if details of all snapshots should be retrieved.
   */
  public function getIdentitySnapshotDetails($snapshot_id) {
    $request_array = array();
    $request_array['snapshotId'] = $snapshot_id;

    return $this->makeRequest('GetIdentitySnapshotDetails', json_encode($request_array), 'miiCard\Consumers\Model\IdentitySnapshotDetails::FromHash', TRUE, TRUE);
  }

  /**
   * Gets the snapshot of a miiCard member's identity by its ID.
   *
   * To discover existing snapshots, use the getIdentitySnapshotDetails
   * function.
   *
   * @param string $snapshot_id
   *   The unique identifier of the snapshot for which details should be
   *   retrieved.
   */
  public function getIdentitySnapshot($snapshot_id) {
    $request_array = array();
    $request_array['snapshotId'] = $snapshot_id;

    return $this->makeRequest('GetIdentitySnapshot', json_encode($request_array), 'miiCard\Consumers\Model\IdentitySnapshot::FromHash', TRUE);
  }

  /**
   * Gets details of how a miiCard member authenticated when authorising.
   *
   * @param string $snapshot_id
   *   The unique identifier of the snapshot for which details should be
   *   retrieved. If no snapshot ID is supplied the most recent authentication
   *   for your application is used instead.
   */
  public function getAuthenticationDetails($snapshot_id = NULL) {
    $request_array = array();
    $request_array['snapshotId'] = $snapshot_id;

    return $this->makeRequest('GetAuthenticationDetails', json_encode($request_array), 'miiCard\Consumers\Model\AuthenticationDetails::FromHash', TRUE);
  }

  /**
   * Gets a PDF of an identity snapshot.
   *
   * @param string $snapshot_id
   *   The unique identifier of the snapshot for which details should be
   *   retrieved.
   */
  public function getIdentitySnapshotPdf($snapshot_id) {
    $request_array = array();
    $request_array['snapshotId'] = $snapshot_id;

    return $this->makeRequest('GetIdentitySnapshotPdf', json_encode($request_array), NULL, FALSE);
  }
}

/**
 * Wrapper around the miiCard Financial API v1.
 *
 * This class wraps the miiCard Financial API v1, exposing the same methods as
 * PHP functions and return types as PHP objects rather than raw JSON.
 *
 * @package MiiCardConsumers
 */
class MiiCardOAuthFinancialService extends MiiCardOAuthServiceBase {
  /**
   * Initialises an MiiCardOAuthFinancialService with specified credentials.
   *
   * If any constructor parameters are omitted, an InvalidArgumentException
   * shall be thrown.
   *
   * @param string $consumer_key
   *   The OAuth consumer key.
   * @param string $consumer_secret
   *   The OAuth consumer secret.
   * @param string $access_token
   *   The OAuth access token.
   * @param string $access_token_secret
   *   The OAuth access token secret.
   */
  public function __construct($consumer_key, $consumer_secret, $access_token, $access_token_secret) {
    parent::__construct($consumer_key, $consumer_secret, $access_token, $access_token_secret);
  }

  /**
  * Gets the URL of a Claims API method
  *
  * @param string $method_name
  *   The name of the API method to call.
  **/
  protected function getMethodUrl($method_name) {
    return MiiCardServiceUrls::getFinancialMethodUrl($method_name);
  }

  /**
   * Determines if a financial data refresh for this member is in progress.
   *
   * Financial data refreshes are generally started by a call to the
   * refreshFinancialData method, though can be system-initiated. Callers should
   * poll this function's result until it returns false, at which point a call
   * to getFinancialTransactions is guaranteed to return the most
   * recently-available financial data.
   *
   **/
  public function isRefreshInProgress() {
    return $this->makeRequest('IsRefreshInProgress', NULL, NULL, TRUE);
  }

  /**
   * Requests that financial data for this member be updated where possible.
   *
   * Whether or not fresh financial data is available depends on a number of
   * factors detailed in the miiCard API documentation available online at
   * www.miicard.com/developers/financial-api. We recommend callers first
   * request financial data from the getFinancialTransactions function and
   * decide whether to request a refresh based upon the last-updated dates of
   * each account within.
   *
   */
  public function refreshFinancialData() {
    return $this->makeRequest('RefreshFinancialData', NULL, 'miiCard\Consumers\Model\FinancialRefreshStatus::FromHash', TRUE);
  }

  /**
   * Obtains financial data for the miiCard member.
   *
   * The set of financial data returned depends on what the miiCard member
   * agreed to share, if anything, and how your API key is configured.
   *
   */
  public function getFinancialTransactions() {
    return $this->makeRequest('GetFinancialTransactions', NULL, 'miiCard\Consumers\Model\MiiFinancialData::FromHash', TRUE);
  }
}

/**
 * Wrapper around the miiCard Directory API v1.
 *
 * This class wraps the miiCard Directory API v1, exposing the same methods as
 * PHP functions and return types as PHP objects rather than raw JSON.
 *
 * @package MiiCardConsumers
 */
class MiiCardDirectoryService {
  const CRITERION_USERNAME = "username";
  const CRITERION_EMAIL = "email";
  const CRITERION_PHONE = "phone";
  const CRITERION_TWITTER = "twitter";
  const CRITERION_FACEBOOK = "facebook";
  const CRITERION_LINKEDIN = "linkedin";
  const CRITERION_GOOGLE = "google";
  const CRITERION_MICROSOFT_ID = "liveid";
  const CRITERION_EBAY = "ebay";
  const CRITERION_VERITAS_VITAE = "veritasvitae";

  /**
   * Finds a miiCard member by their published email address.
   *
   * @param string $email_address
   *   The member's published email address
   * @param bool $hashed
   *   Specifies whether $email_address has been SHA-1 hashed for privacy
   */
  public function findByEmail($email_address, $hashed = FALSE) {
    return $this->findBy(CRITERION_EMAIL, $email_address, $hashed);
  }

  /**
   * Finds a miiCard member by their published phone number.
   *
   * @param string $phone_number
   *   The member's published phone number.
   * @param bool $hashed
   *   Specifies whether $phone_number has been SHA-1 hashed for privacy
   */
  public function findByPhoneNumber($phone_number, $hashed = FALSE) {
    return $this->findBy(CRITERION_PHONE, $phone_number, $hashed);
  }

  /**
   * Finds a miiCard member by their published username.
   *
   * @param string $username
   *   The member's published username.
   * @param bool $hashed
   *   Specifies whether $username has been SHA-1 hashed for privacy
   */
  public function findByUsername($username, $hashed = FALSE) {
    return $this->findBy(CRITERION_USER, $username, $hashed);
  }

  /**
   * Finds a miiCard member by their published Twitter handle or profile URL.
   *
   * @param string $twitter_handle_or_url
   *   The member's published Twitter handle (like @miicard) or profile URL
   *   (like https://twitter.com/miicard).
   * @param bool $hashed
   *   Specifies whether $twitter_handle_or_url has been SHA-1 hashed for
   *   privacy.
   */
  public function findByTwitter($twitter_handle_or_url, $hashed = FALSE) {
    return $this->findBy(CRITERION_TWITTER, $twitter_handle_or_url, $hashed);
  }

  /**
   * Finds a miiCard member by their published Facebook profile URL.
   *
   * @param string $facebook_url
   *   The member's published Facebook profile URL (like
   *   https://www.facebook.com/miiCard).
   * @param bool $hashed
   *   Specifies whether $facebook_handle_or_profile_url has been SHA-1 hashed
   *   for privacy.
   */
  public function findByFacebook($facebook_url, $hashed = FALSE) {
    return $this->findBy(CRITERION_FACEBOOK, $facebook_url, $hashed);
  }

  /**
   * Finds a miiCard member by their published LinkedIn or profile URL.
   *
   * @param string $linkedin_www_url
   *   The member's published non-localised LinkedIn profile URL.
   * @param bool $hashed
   *   Specifies whether $linkedin_www_url has been SHA-1 hashed
   *   for privacy.
   */
  public function findByLinkedIn($linkedin_www_url, $hashed = FALSE) {
    return $this->findBy(CRITERION_LINKEDIN, $linkedin_www_url, $hashed);
  }

  /**
   * Finds a miiCard member by their published Google+ handle or profile URL.
   *
   * @param string $google_plus_handle_or_profile_url
   *   The member's published Google+ handle or profile URL.
   * @param bool $hashed
   *   Specifies whether $google_plus_handle_or_profile_url has been SHA-1
   *   hashed for privacy.
   */
  public function findByGoogle($google_plus_handle_or_profile_url, $hashed = FALSE) {
    return $this->findBy(CRITERION_GOOGLE, $google_plus_handle_or_profile_url, $hashed);
  }

  /**
   * Finds a miiCard member by their published Microsoft ID profile URL.
   *
   * @param string $microsoft_id_url
   *   The member's published Microsoft ID profile URL.
   * @param bool $hashed
   *   Specifies whether $microsoft_id_url has been SHA-1
   *   hashed for privacy.
   */
  public function findByMicrosoftId($microsoft_id_url, $hashed = FALSE) {
    return $this->findBy(CRITERION_MICROSOFT_ID, $microsoft_id_url, $hashed);
  }

  /**
   * Finds a miiCard member by their published eBay ID or profile URL.
   *
   * @param string $ebay_handle_or_profile_url
   *   The member's published eBay ID or profile URL.
   * @param bool $hashed
   *   Specifies whether $ebay_handle_or_profile_url has been SHA-1
   *   hashed for privacy.
   */
  public function findByEbay($ebay_handle_or_profile_url, $hashed = FALSE) {
    return $this->findBy(CRITERION_EBAY, $ebay_handle_or_profile_url, $hashed);
  }

  /**
   * Finds a miiCard member by their published Veritas Vitae ID or profile URL.
   *
   * @param string $veritas_vitae_vv_number_or_profile_url
   *   The member's published Veritas Vitae ID or profile URL.
   * @param bool $hashed
   *   Specifies whether $veritas_vitae_vv_number_or_profile_url has been SHA-1
   *   hashed for privacy.
   */
  public function findByVeritasVitae($veritas_vitae_vv_number_or_profile_url, $hashed = FALSE) {
    return $this->findBy(CRITERION_VERITAS_VITAE, $veritas_vitae_vv_number_or_profile_url, $hashed);
  }

  /**
   * Hashes an identifier with SHA1.
   *
   * To protect the privacy of your users you may elect to search the Directory
   * API by supplying a hash of the identifier instead of the identifier itself.
   * However, this approach gives the Directory API very little margin for error
   * when looking up a miiCard member - the hash must exactly match an expected
   * value at the server side, whereas sending an unhashed value allows the
   * Directory API to perform some processing and normalisation for a higher
   * success rate.
   *
   * @param string $identifier
   *   The identifier to be hashed. The identifier is lowercased before hashing
   *   but not otherwise normalised.
   */
  public static function hashIdentifier($identifier) {
    // When sending a parameter hashed we need to lower-case it as a normalisation step. The API
    // expects a 40-character hex string but the sha1 method gives us that by default.
    return sha1(strtolower($identifier));
  }

  /**
   * Finds a miiCard member by a piece of data published to their profile.
   *
   * @param string $criterion
   *   The criterion being sought - see the constants of this class.
   * @param string $value
   *   The value of the criterion for the sought miiCard member.
   * @param bool $hashed
   *   Specifies whether $value has been SHA-1 hashed for privacy.
   * @param bool $unwrap
   *   Specifies whether a whole MiiApiResponse should be returned, or just
   *   the user profile/NULL on success/failure respectively.
   */
  public function findBy($criterion, $value, $hashed = FALSE) {
    $url = MiiCardServiceUrls::getDirectoryServiceQueryUrl($criterion, $value, $hashed);
    $uri = @parse_url($url);
    $path = isset($uri['path']) ? $uri['path'] : '/';

    if (isset($uri['query'])) {
      $path .= '?' . $uri['query'];
    }

    $start = microtime(TRUE);
    $port = isset($uri['port']) ? $uri['port'] : 443;
    $socket = 'ssl://' . $uri['host'] . ':' . $port;
    $headers = array(
      'Accept:',
      'Host: ' . $uri['host'] . ($port != 443 ? ':' . $port : ''),
      'User-Agent: miiCard PHP',
      'Content-Type: application/json'
    );

    $curl_options = array(
      CURLOPT_URL => $url,
      CURLOPT_CONNECTTIMEOUT => 90,
      CURLOPT_TIMEOUT => 90,
      CURLOPT_FOLLOWLOCATION => TRUE,
      CURLOPT_RETURNTRANSFER => TRUE,
      CURLOPT_SSL_VERIFYHOST => MIICARD_VERIFY_SSL_DETAILS,
      CURLOPT_SSL_VERIFYPEER => MIICARD_VERIFY_SSL_DETAILS ? 2 : 0,
      CURLOPT_CAINFO => dirname(__FILE__) . "/certs/sts.miicard.com.pem",
      CURLOPT_HTTPHEADER => $headers,
      CURLOPT_FORBID_REUSE => TRUE,
      CURLOPT_FRESH_CONNECT => TRUE,
    );

    $ch = curl_init();
    curl_setopt_array($ch, $curl_options);
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($response != NULL) {
      $response = json_decode($response, TRUE);

      $to_return = Model\MiiApiResponse::FromHash($response, 'miiCard\Consumers\Model\MiiUserProfile::FromHash');
      $to_return = $to_return->getData();

      return $to_return;
    }
    else {
      return NULL;
    };
  }
}

/**
 * Wrapper around the miiCard OAuth authorisation process.
 *
 * @package MiiCardConsumers
 */
class MiiCard extends OAuthSignedRequestMaker {
  /** The callback URL that the OAuth process will return to once completed. */
  protected $callbackUrl;
  /** The affiliate code to send with the request. */
  protected $referrerCode;
  /** Sets whether to force the user to re-select information to share. */
  protected $forceClaimsPicker;
  /** Sets whether to initially direct the user to a signup page. */
  protected $signupMode;

  /** @access private */ const SESSION_KEY_ACCESS_TOKEN = "miiCard.OAuth.InProgress.AccessToken";
  /** @access private */ const SESSION_KEY_ACCESS_TOKEN_SECRET = "miiCard.OAuth.InProgress.AccessTokenSecret";

  /**
   * Builds a new MiiCard object using the supplied OAuth credentials.
   *
   * @param string $consumer_key
   *   The OAuth consumer key.
   * @param string $consumer_secret
   *   The OAuth consumer secret.
   * @param string $access_token
   *   The OAuth access token.
   * @param string $access_token_secret
   *   The OAuth access token secret.
   * @param string $referrer_code
   *   Your referrer code, if you have one.
   * @param string $callback_url
   *   Set a customer callback url.
   */
  public function __construct($consumer_key, $consumer_secret, $access_token = NULL, $access_token_secret = NULL, $referrer_code = NULL, $force_claims_picker = FALSE, $callback_url = NULL,$signup_mode = FALSE) {
    parent::__construct($consumer_key, $consumer_secret, $access_token, $access_token_secret);

    $this->callbackUrl = $this->getDefaultCallbackUrl($callback_url);
    $this->referrerCode = $referrer_code;
    $this->forceClaimsPicker = isset($force_claims_picker) ? $force_claims_picker : FALSE;
    $this->signupMode = isset($signup_mode) ? $signup_mode : FALSE;
  }

  /**
   * Gets the access token with which requests should be signed.
   */
  public function getAccessToken() {
    $to_return = parent::getAccessToken();
    if ($to_return == NULL && isset($_SESSION) && isset($_SESSION[MiiCard::SESSION_KEY_ACCESS_TOKEN])) {
      $to_return = $_SESSION[MiiCard::SESSION_KEY_ACCESS_TOKEN];
    }

    return $to_return;
  }

  /**
   * Gets the access token secret with which requests should be signed.
   */
  public function getAccessTokenSecret() {
    $to_return = parent::getAccessTokenSecret();
    if ($to_return == NULL && isset($_SESSION) && isset($_SESSION[MiiCard::SESSION_KEY_ACCESS_TOKEN_SECRET])) {
      $to_return = $_SESSION[MiiCard::SESSION_KEY_ACCESS_TOKEN_SECRET];
    }

    return $to_return;
  }

  /**
   * Gets the default callback URL to return to once the OAuth flow completes.
   */
  public function getDefaultCallbackUrl($callback_url = NULL) {
  	if(!isset($callback_url))
  	{
	  	$is_https = isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on';
	  	$http_protocol = $is_https ? 'https' : 'http';
	  	return $http_protocol . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
  	}
  	else
  	{
	  	return $callback_url;
  	}
    
  }

  /**
   * Starts an OAuth authorisation process.
   *
   * Your script must not have sent any HTML content to the
   * browser at the point when this is called, and should have called
   * session_start().
   *
   * @param string $callback_url
   *   The URL that should be returned to after the OAuth process completes.
   *   This is automatically detected if not supplied.
   */
  public function beginAuthorisation($callback_url = NULL) {
    $this->ensureSessionAvailable();
    $this->clearMiiCard();

    if (isset($callback_url)) {
      $this->callbackUrl = $callback_url;
    }

    $request_token = $this->getRequestToken();

    $this->accessToken = $request_token->key;
    $this->accessTokenSecret = $request_token->secret;

    $_SESSION[MiiCard::SESSION_KEY_ACCESS_TOKEN] = $this->getAccessToken();
    $_SESSION[MiiCard::SESSION_KEY_ACCESS_TOKEN_SECRET] = $this->getAccessTokenSecret();

    $redirect_url = MiiCardServiceUrls::OAUTH_ENDPOINT . "?oauth_token=" . rawurlencode($request_token->key);
    if (isset($this->referrerCode) && $this->referrerCode != NULL) {
      $redirect_url .= "&referrer=" . $this->referrerCode;
    }

    if (isset($this->forceClaimsPicker) && $this->forceClaimsPicker == TRUE) {
      $redirect_url .= "&force_claims=true";
    }

    if (isset($this->signupMode) && $this->signupMode == TRUE) {
      $redirect_url .= "&signup=true";
    }

    // Doing a header here means we never set the session cookie, which is bad
    // if we're the first thing that ever tries as we'll forget the request
    // token secret. Instead, do a quick bounce through a meta refresh.
    /*
        <html><head><meta http-equiv="refresh" content="0;url=<?php echo $redirect_url ?>"></head><title>Redirecting to miiCard.com</title>
        <body>You should be redirected automatically - if not, <a href="<?php echo $redirect_url ?>">click here</a>.</body></html>
    */
    
    require'template.php'; 

    exit(0);
  }

  /**
   * Determines if the current request is an OAuth callback.
   *
   * The caller should check this function on each page load of the callback
   * page, and attempt to handle the OAuth callback only in the event that it
   * returns TRUE.
   */
  public function isAuthorisationCallback() {
    return isset($_GET['oauth_verifier']);
  }

  /**
   * Processes the OAuth callback, obtaining an access token and secret.
   *
   * The caller should check the return value of the isAuthorisationSuccess
   * function after trying to handle the callback.
   */
  public function handleAuthorisationCallback() {
    $this->ensureSessionAvailable();

    $token = array_key_exists('oauth_token', $_REQUEST) ? $_REQUEST['oauth_token'] : '';
    $verifier = array_key_exists('oauth_verifier', $_REQUEST) ? $_REQUEST['oauth_verifier'] : '';

    if (empty($token) || empty($verifier)) {
      return;
    }

    $this->processAccessToken($verifier);
  }

  /**
   * Determines if obtaining OAuth access token and secret information suceeded.
   *
   * If TRUE, the caller can obtain the two tokens using the getAccessToken and
   * getAccessTokenSecret functions.
   */
  public function isAuthorisationSuccess() {
    return $this->getAccessToken() != NULL && $this->getAccessTokenSecret() != NULL;
  }

  /**
   * Gets the identity claims the miiCard member elected to share.
   *
   * This is a convenience method, and building a MiiCardOAuthClaimsService
   * object is the preferred approach.
   */
  public function getUserProfile() {
    if ($this->getAccessToken() == NULL || $this->getAccessTokenSecret() == NULL) {
      throw new MiiCardException("You must set the access token and access token secret to make calls into the miiCard API");
    }
    else {
      $api = new MiiCardOAuthClaimsService($this->getConsumerKey(), $this->getConsumerSecret(), $this->getAccessToken(), $this->getAccessTokenSecret());
      $response = $api->getClaims();

      if ($response->getStatus() == Model\MiiApiCallStatus::SUCCESS) {
        return $response->getData();
      }
      else {
        return NULL;
      }
    }
  }

  /**
   * Clears any OAuth credentials that might be stored.
   *
   * This is called automatically by the beginAuthorisation method.
   */
  public function clearMiiCard() {
    if (isset($_SESSION)) {
      $_SESSION[MiiCard::SESSION_KEY_ACCESS_TOKEN] = NULL;
      $_SESSION[MiiCard::SESSION_KEY_ACCESS_TOKEN_SECRET] = NULL;
    }
  }

  /**
   * Obtains an OAuth request token from the miiCard OAuth endpoint.
   */
  protected function getRequestToken() {
    $url = MiiCardServiceUrls::OAUTH_ENDPOINT;
    $params = array('oauth_callback' => $this->callbackUrl);

    $response = $this->makeSignedRequest($url, $params);
    parse_str($response, $token);

    if (!array_key_exists('oauth_token', $token)) {
      throw new MiiCardException("No token received from OAuth service - check credentials");
    }

    return new \OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
  }

  /**
   * Converts a request token into a fully-fledged access token.
   *
   * @param string $verifier
   *   The server supplied verifier that signifies the request token has been
   *   authorised by the miiCard member.
   */
  protected function processAccessToken($verifier) {
    $url = MiiCardServiceUrls::OAUTH_ENDPOINT;
    $params = array('oauth_verifier' => $verifier);

    $response = $this->makeSignedRequest($url, $params);
    if (empty($response)) {
      throw new MiiCardException('Nothing received from miiCard');
    }
    parse_str($response, $token);

    $this->accessToken = $token['oauth_token'];
    $_SESSION[MiiCard::SESSION_KEY_ACCESS_TOKEN] = $token['oauth_token'];

    $this->accessTokenSecret = $token['oauth_token_secret'];
    $_SESSION[MiiCard::SESSION_KEY_ACCESS_TOKEN_SECRET] = $token['oauth_token_secret'];

    return new \OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
  }

  /**
   * Attempts to make sure that session state is available.
   */
  protected function ensureSessionAvailable() {
    if (session_id() == "") {
      // Save current session data before starting it, as PHP will destroy it.
      $session_data = isset($_SESSION) ? $_SESSION : NULL;
      session_start();

      // Restore session data.
      if (!empty($session_data)) {
        $_SESSION += $session_data;
      }
    }
  }
}
