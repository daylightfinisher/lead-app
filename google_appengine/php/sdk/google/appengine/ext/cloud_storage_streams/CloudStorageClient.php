<?php
/**
 * Copyright 2007 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * CloudStorageClient is the base class for classes that are used to communicate
 * with Google Cloud Storage via the PHP streams interface.
 *
 */

namespace google\appengine\ext\cloud_storage_streams;

require_once 'google/appengine/api/app_identity/AppIdentityService.php';
require_once 'google/appengine/api/cloud_storage/CloudStorageTools.php';
require_once 'google/appengine/api/urlfetch_service_pb.php';
require_once 'google/appengine/ext/cloud_storage_streams/HttpResponse.php';
require_once 'google/appengine/runtime/ApiProxy.php';
require_once 'google/appengine/runtime/ApplicationError.php';
require_once 'google/appengine/util/array_util.php';

use google\appengine\api\app_identity\AppIdentityService;
use google\appengine\api\app_identity\AppIdentityException;
use google\appengine\api\cloud_storage\CloudStorageTools;
use google\appengine\runtime\ApiProxy;
use google\appengine\runtime\ApplicationError;
use google\appengine\URLFetchRequest\RequestMethod;
use google\appengine\util as util;

/**
 * CloudStorageClient provides default fail implementations for all of the
 * methods that the stream wrapper might potentially call. Derived classes then
 * only implement the methods that are relevant to the operations that they
 * perform.
 */
abstract class CloudStorageClient {
  // The default chunk size that we will read from the file. This value should
  // remain smaller than the maximum object size valid for memcache writes so
  // we can cache the reads.
  const DEFAULT_READ_SIZE = 524288;

  // The default amount of time that reads will be held in the cache.
  const DEFAULT_READ_CACHE_EXPIRY_SECONDS = 3600;  // one hour

  // The default time the writable state of a bucket will be cached for.
  const DEFAULT_WRITABLE_CACHE_EXPIRY_SECONDS = 600;  // ten minutes

  // Token scopers for accessing objects in Google Cloud Storage
  const READ_SCOPE = "https://www.googleapis.com/auth/devstorage.read_only";
  const WRITE_SCOPE = "https://www.googleapis.com/auth/devstorage.read_write";
  const FULL_SCOPE = "https://www.googleapis.com/auth/devstorage.full_control";

  // Format for the OAuth token header.
  const OAUTH_TOKEN_FORMAT = "OAuth %s";

  // Content Range Header format when the total length is unknown.
  const PARTIAL_CONTENT_RANGE_FORMAT = "bytes %d-%d/*";

  // Content Range Header format when the length is known.
  const FINAL_CONTENT_RANGE_FORMAT = "bytes %d-%d/%d";

  // Content Range Header for final chunk with no new data
  const FINAL_CONTENT_RANGE_NO_DATA = "bytes */%d";

  // A character or multiple characters that can be used to simplify a list of
  // objects that use a directory-like naming scheme. Can be used in conjunction
  // with a prefix.
  const DELIMITER = '/';

  // Cloud storage can append _$folder$ to an object name and have it behave
  // like a regular file system folder.
  const FOLDER_SUFFIX = '_$folder$';

  // Temporary file name we create when checking if a bucket is writable.
  const WRITABLE_TEMP_FILENAME = "/_ah_is_writable_temp_file";

  // Bit fields for the stat mode field
  const S_IFREG = 0100000;
  const S_IFDIR = 0040000;

  const S_IRWXU = 00700;  // mask for owner permissions
  const S_IRUSR = 00400;  // read for owner
  const S_IWUSR = 00200;  // write for owner
  const S_IXUSR = 00100;  // execute for owner

  const S_IRWXG = 00070;  // mask for group permissions
  const S_IRGRP = 00040;  // read for group
  const S_IWGRP = 00020;  // write for group
  const S_IXGRP = 00010;  // execute for group

  const S_IRWXO = 00007;  // mask for other other permissions
  const S_IROTH = 00004;  // read for other
  const S_IWOTH = 00002;  // write for other
  const S_IXOTH = 00001;  // execute for other

  // The API version header
  private static $api_version_header = ["x-goog-api-version" => 2];

  // Regex patterm for retrieving the Length of the content being served.
  const CONTENT_RANGE_REGEX = "/bytes\s+(\d+)-(\d+)\/(\d+)/i";

  /**
   * Memcache key format for caching the results of reads from GCS. The
   * parameters are the object url (as a string) and the read range, as a
   * string (e.g. bytes=0-512000).
   * Example key for a cloud storage file gs://bucket/object.png
   *   _ah_gs_read_cache_https://storage.googleapis.com/bucket/object.png_bytes=0-524287
   */
  const MEMCACHE_KEY_FORMAT = "_ah_gs_read_cache_%s_%s";

  /**
   * Memcache key format for caching the results of checking if a bucket is
   * writable. The only way to check if an app can write to a bucket is by
   * actually writing a file. As the ACL on a bucket is unlikely to change
   * then we can cache the result.
   */
  const WRITABLE_MEMCACHE_KEY_FORMAT = "_ah_gs_write_bucket_cache_%s";

  // HTTP status codes that should be retried if they are returned by a request
  // to GCS. Retry should occur with a random exponential back-off.
  protected static $retry_error_codes = [HttpResponse::REQUEST_TIMEOUT,
                                         HttpResponse::INTERNAL_SERVER_ERROR,
                                         HttpResponse::BAD_GATEWAY,
                                         HttpResponse::SERVICE_UNAVAILABLE,
                                         HttpResponse::GATEWAY_TIMEOUT];

  // Values that are allowed to be supplied as ACLs when writing objects.
  protected static $valid_acl_values = ["private",
                                        "public-read",
                                        "public-read-write",
                                        "authenticated-read",
                                        "bucket-owner-read",
                                        "bucket-owner-full-control"];

 protected static $upload_start_header = ["x-goog-resumable" => "start"];

  // Map HTTP request types to URLFetch method enum.
  private static $request_map = [
      "GET" => RequestMethod::GET,
      "POST" => RequestMethod::POST,
      "HEAD" => RequestMethod::HEAD,
      "PUT" => RequestMethod::PUT,
      "DELETE" => RequestMethod::DELETE,
      "PATCH" => RequestMethod::PATCH
  ];

  private static $default_gs_context_options = [
      "enable_cache" => true,
      "enable_optimistic_cache" => false,
      "read_cache_expiry_seconds" => self::DEFAULT_READ_CACHE_EXPIRY_SECONDS,
      "writable_cache_expiry_seconds" =>
          self::DEFAULT_WRITABLE_CACHE_EXPIRY_SECONDS,
  ];

  protected $bucket_name;  // Name of the bucket for this object.
  protected $object_name;  // The name of the object.
  protected $context_options = [];  // Any context arguments supplied on open.
  protected $url;  // GCS URL of the object.
  protected $anonymous;  // Use anonymous access when contacting GCS.

  /**
   * Construct an object of CloudStorageClient.
   *
   * @param string $bucket The name of the bucket.
   * @param string $object The name of the object, or null if there is no
   * object.
   * @param resource $context The stream context to use.
   */
  public function __construct($bucket, $object = null, $context = null) {
    $this->bucket_name = $bucket;
    $this->object_name = $object;
    if (!isset($context)) {
      $context = stream_context_get_default();
    }
    $context_array = stream_context_get_options($context);
    if (array_key_exists("gs", $context_array)) {
      $this->context_options = array_merge(self::$default_gs_context_options,
                                           $context_array["gs"]);
    } else {
      $this->context_options = self::$default_gs_context_options;
    }
    $this->anonymous = util\findByKeyOrNull($this->context_options,
                                            "anonymous");

    $this->url = $this->createObjectUrl($bucket, $object);
  }

  public function __destruct() {
  }

  public function initialize() {
    return false;
  }

  public function dir_readdir() {
    return false;
  }

  public function dir_rewinddir() {
    return false;
  }

  // @return nothing
  public function close() {
  }

  public function delete() {
    return false;
  }

  public function eof() {
    return true;
  }

  public function flush() {
    return true;
  }

  public function read($count_bytes) {
    return false;
  }

  public function seek($offset, $whence) {
    return false;
  }

  public function stat() {
    return false;
  }

  public function tell() {
    return false;
  }

  public function write($data) {
    return false;
  }

  /**
   * Get the OAuth Token HTTP header for the supplied scope.
   *
   * @param $scopes mixed The scopes to acquire the token for.
   *
   * @return array The HTTP authorization header for the scopes, using the
   * applications service account. False if the call failed.
   */
  protected function getOAuthTokenHeader($scopes) {
    if ($this->anonymous) {
      return [];
    }

    try {
      $token = AppIdentityService::getAccessToken($scopes);
      return ["Authorization" => sprintf(self::OAUTH_TOKEN_FORMAT,
                                         $token['access_token'])];
    } catch (AppIdentityException $e) {
      return false;
    }
  }

  /**
   * Create a URL for a target bucket and optional object.
   *
   * @visibleForTesting
   */
  public static function createObjectUrl($bucket, $object = null) {
    // Strip leading "/" for $object
    if (isset($object) && $object[0] == "/") {
      $object_name = substr($object, 1);
    } else {
      $object_name = "";
    }

    $gs_filename = CloudStorageTools::getFilename($bucket, $object_name);
    return CloudStorageTools::getPublicUrl($gs_filename, true);
  }

  /**
   * Return a Range HTTP header.
   *
   * @param $start_byte int The offset of the first byte in the range.
   * @param $end_byte int The offset of the last byte in the range.
   *
   * @return array The HTTP Range header for the supplied offsets.
   */
  protected function getRangeHeader($start_byte, $end_byte) {
    assert($start_byte <= $end_byte);
    return ["Range" => sprintf("bytes=%d-%d", $start_byte, $end_byte)];
  }

  /**
   * Make a request to GCS using HttpStreams.
   *
   * Returns:
   * headers array
   * response body
   */
  protected function makeHttpRequest($url, $method, $headers, $body = null) {
    $request_headers = array_merge($headers, self::$api_version_header);

    $result = $this->doHttpRequest($url,
                                   $method,
                                   $request_headers,
                                   $body);

    if ($result === false) {
      return false;
    }

    return [
      'status_code' => $result['status_code'],
      'headers' => $result['headers'],
      'body' => $result['body'],
    ];
  }

  /**
   * Return the value of a header stored in an associative array, using a case
   * insensitive comparison on the header name.
   *
   * @param $header_name string The name of the header to lookup.
   * @param $headers array Associative array of headers.
   *
   * @return The value of the header if found, false otherwise.
   */
  protected function getHeaderValue($header_name, $headers) {
    // Could be more than one header, in which case we keep an array.
    foreach($headers as $key => $value) {
      if (strcasecmp($key, $header_name) === 0) {
        return $value;
      }
    }
    return null;
  }

  /**
   *
   */
  private function doHttpRequest($url, $method, $headers, $body) {
    $req = new \google\appengine\URLFetchRequest();
    $req->setUrl($url);
    $req->setMethod(self::$request_map[$method]);
    $req->setMustValidateServerCertificate(true);
    if (isset($body)) {
      $req->setPayload($body);
    }

    foreach($headers as $key => $value) {
      $h = $req->addHeader();
      $h->setKey($key);
      $h->setValue($value);
    }

    $resp = new \google\appengine\URLFetchResponse();

    try {
      ApiProxy::makeSyncCall('urlfetch', 'Fetch', $req, $resp);
    } catch (ApplicationError $e) {
      syslog(LOG_ERR,
             sprintf("Call to URLFetch failed with application error %d.",
                     $e->getApplicationError()));
      return false;
    }

    $response_headers = [];
    foreach($resp->getHeaderList() as $header) {
      // TODO: Do we need to support multiple headers with the same key?
      $response_headers[trim($header->getKey())] = trim($header->getValue());
    }

    return [
      'status_code' => $resp->getStatusCode(),
      'headers' => $response_headers,
      'body' => $resp->getContent(),
    ];
  }

  /**
   * Generate the default stat() array, which is both associative and index
   * based.
   *
   * @access private
   */
  protected function createStatArray($stat_args) {
    $stat_keys = ["dev", "ino", "mode", "nlink", "uid", "gid", "rdev", "size",
        "atime", "mtime", "ctime", "blksize", "blocks"];

    $result = [];

    foreach ($stat_keys as $key) {
      $value = 0;
      if (array_key_exists($key, $stat_args)) {
        $value = $stat_args[$key];
      }
      // Add the associative entry.
      $result[$key] = $value;
      // Add the index entry.
      $result[] = $value;
    }

    return $result;
  }

  /**
   * Given an xml based error response from Cloud Storage, try and extract the
   * error code and error message according to the schema described at
   * https://developers.google.com/storage/docs/reference-status
   *
   * @param string $gcs_result The response body of the last call to Google
   * Cloud Storage.
   * @param string $code Reference variable where the error code for the last
   * message will be returned.
   * @param string $message Reference variable where the error detail for the
   * last message will be returned.
   * @return bool True if the error code and message could be extracted, false
   * otherwise.
   */
  protected function tryParseCloudStorageErrorMessage($gcs_result,
                                                      &$code,
                                                      &$message) {
    $code = null;
    $message = null;

    $old_errors = libxml_use_internal_errors(true);
    $xml = simplexml_load_string($gcs_result);

    if (false != $xml) {
      $code = (string) $xml->Code;
      $message = (string) $xml->Message;
    }
    libxml_use_internal_errors($old_errors);
    return (isset($code) && isset($message));
  }

  /**
   * Return a formatted error message for the http response.
   *
   * @param int $http_status_code The HTTP status code returned from the last
   * http request.
   * @param string $http_result The response body from the last http request.
   * @param string $msg_prefix The prefix to add to the error message that will
   * be generated.
   *
   * @return string The error message for the last HTTP response.
   */
  protected function getErrorMessage($http_status_code,
                                     $http_result,
                                     $msg_prefix = "Cloud Storage Error:") {
    if ($this->tryParseCloudStorageErrorMessage($http_result,
                                                $code,
                                                $message)) {
      return sprintf("%s %s (%s)", $msg_prefix, $message, $code);
    } else {
      return sprintf("%s %s",
                     $msg_prefix,
                     HttpResponse::getStatusMessage($http_status_code));
    }
  }

}
