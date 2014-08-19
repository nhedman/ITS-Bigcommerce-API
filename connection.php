<?php
/**
 *Class to instantiate different Bigcommerce API connections under the new OAuth scheme
 * 
 * @author Adam Bilsing <adambilsing@gmail.com>
 * @author Nathaniel Hedman <nhedman@intuitsolutions.net>
 */
class Connection
{
	/**
	 *public and private variables 
	 *
	 * @var string stores data for the class
	 */
	static public $_hash;
	static private $_client;
	static private $_token;
	static private $_headers;
	static private $_curl;
	private $retries = 0;
	const RETRY_ATTEMPTS = 5;


	/**
	 * Sets $_hash, $_client, $_token, $_headers, $_curl upon class instantiation 
	 *
	 * @param $clientId, $storeHash, $token required for the class
	 * @return void
	 */
	public function __construct($clientId, $storeHash, $token) {
		$this->_hash = $storeHash;
		$this->_client = $clientId;
		$this->_token = $token;

		$clientHeaderString = 'X-Auth-Client: ' . $this->_client;
		$tokenHeaderString = 'X-Auth-Token: ' . $this->_token;
		$this->_headers = array($tokenHeaderString, $clientHeaderString, 'Accept: application/json','Content-Type: application/json');
		$this->_curl = curl_init();
		curl_setopt($this->_curl, CURLOPT_HTTPHEADER, $this->_headers);
		curl_setopt($this->_curl, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($this->_curl, CURLOPT_VERBOSE, 1);
		curl_setopt($this->_curl, CURLOPT_HEADER, 1);
		curl_setopt($this->_curl, CURLOPT_SSL_VERIFYPEER, false);  
	}


	/**
	 * Performs POST request to Bc API for response to Auth Callback Request
	 * 
	 * Accepts app credentials and grant information
	 *
	 * @param $client_id, $client_secret, $redirect_uri, $code, $scope, $context required for granting auth_token
	 * @return stdClass with fields properties access_token, scope, user (user.id, user.username, user.email), context
	 */
	public static function getAccessToken($client_id, $client_secret, $redirect_uri, $code, $scope, $context)
	{
		$data = array(
    		"client_id" => $client_id,
    		"client_secret" => $client_secret,
    		"redirect_uri" => $redirect_uri,
    		"grant_type" => "authorization_code",
    		"code" => $code,
    		"scope" => $scope,
    		"context" => $context,
		);

		$postfields = http_build_query($data);

		$ch = curl_init();                     
		$url = "https://login.bigcommerce.com/oauth2/token";
		curl_setopt($ch, CURLOPT_URL,$url);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $postfields);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		$response = curl_exec ($ch);
		$http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		curl_close ($ch);
		
		if ($http_status == 200) {
			$results = json_decode($response);
			return $results;
		} else {
			return false;
		}
	}

	/**
	 * Handle GET request for Load Callback and deep links, should probably be preceded 
	 * by checking if valid session already exists and followed by adding storeHash and
	 * accessToken to session.
	 * No parameters
	 * 
	 * @param void
	 * @return stdClass with fields user.id, user.email, user.store_hash, null if invalid
	 */

	public static function load() 
	{
		$signedRequest = $_GET['signed_payload'];
		$valid = self::verify($signedRequest);
		if ($valid) {
			$storeHash = $valid->store_hash;
			//valid access request, you should retrieve accessToken from application persistence using $storeHash
			return $storeHash;
		} else {
			return false;
		}
	}

	/**
	 * Verify and decode GET request for Load Callback and deep links
	 * 
	 * Accepts signed request
	 * 
	 * @param $signedRequest, get variable sent by Bigcommerce
	 * @return stdClass with fields user.id, user.email, user.store_hash, null if invalid
	 */

	public static function verify($signedRequest) {
		list($payload, $encodedSignature) = explode('.', $signedRequest, 2); 

		// decode the data
		$signature = base64_decode($encodedSignature);
		$data = json_decode(base64_decode($payload));

		// confirm the signature
		$expectedSignature = hash_hmac('sha256', $payload, CLIENT_SECRET, $raw = true);
	
		if (secureCompare($signature, $expectedSignature)) {
			return null;
		}

		return $data;
	}

	/**
	 * Time-invariant comparison of strings to foil timing attacks
	 * 
	 * Accepts strings for comparison
	 * 
	 * @param $str1, $str2 strings for
	 * @return boolean, false if not identical
	 */

	static function secureCompare($str1, $str2) {
		$res = $str1 ^ $str2;
		$ret = strlen($str1) ^ strlen($str2); //not the same length, then fail ($ret != 0)
		for($i = strlen($res) - 1; $i >= 0; $i--) {
			$ret += ord($res[$i]);
		}
		return !$ret;
	}

	/**
	 * Implementation of http_parse_headers for PHP without PECL
	 * 
	 * Accepts string response header
	 * 
	 * @param $header, string response header
	 * @return array
	 */

	public static function http_parse_headers( $header )
    {
        $retVal = array();
        $fields = explode("\r\n", preg_replace('/\x0D\x0A[\x09\x20]+/', ' ', $header));
        foreach( $fields as $field ) {
            if( preg_match('/([^:]+): (.+)/m', $field, $match) ) {
                $match[1] = preg_replace('/(?<=^|[\x09\x20\x2D])./e', 'strtoupper("\0")', strtolower(trim($match[1])));
                if( isset($retVal[$match[1]]) ) {
                    $retVal[$match[1]] = array($retVal[$match[1]], $match[2]);
                } else {
                    $retVal[$match[1]] = trim($match[2]);
                }
            }
        }
        return $retVal;
    }

	/**
	 * Controls rate of request to API based on response headers
	 * 
	 * Accepts array response headers
	 * 
	 * @param $headers, array response headers
	 * @return boolean, false (with sleep) if rate limit currently reached, true if limit ok
	 */

    public function rate_limit( $headers )
    {
    	if (@$headers['X-Retry-After'] > 0) {
        	sleep($headers['X-Retry-After']);
			return false;
        }
      	
        $this->retries = 0;
        return true;
    }

	/**
	 * Lodges an error based on current request
	 * 
	 * Accepts the response body, url, json encoded information and request type
	 * 
	 * @param $body, response body, $url, request url, $json, $json encoded response, $type request type
	 * @return void, sets array $error
	 */

    public function error($body, $url, $json, $type) {
    	global $error;
    	if (isset($json)) {
	    	$results = json_decode($body, true);
			$results = $results[0];
			$results['type'] = $type;
			$results['url'] = $url;
			$results['payload'] = $json;
			$error = $results;
		} else {
			$results = json_decode($body, true);
			$results = $results[0];
			$results['type'] = $type;
			$results['url'] = $url;
			$error = $results;
		}
    }

	/**
	 * Performs a get request to the instantiated class
	 * 
	 * Accepts the resource to perform the request on
	 * 
	 * @param $resource string $resource a string to perform get on
	 * @return stdClass results or var_dump error
	 */
	public function get($resource, array $filter = null) {

		$url = 'https://api.bigcommerce.com/stores/' . $this->_hash . '/v2/' . $resource;
		if ( $filter ) {
			$url .= '?' . http_build_query($filter);
		}

		curl_setopt($this->_curl, CURLOPT_URL, $url);
		curl_setopt($this->_curl, CURLOPT_HTTPGET, 1);          
		$response = curl_exec($curl);
		$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
		$headers = substr($response, 0, $header_size);
		$body = substr($response, $header_size);
		$headersArray = self::http_parse_headers($headers);
		if (! $this->rate_limit($headersArray) && $this->retries < self::RETRY_ATTEMPTS) {
			$this->retries = $this->retries + 1;
			return $this->get($resource, $filter);
		}
		if ($http_status == 200) {
			$results = json_decode($body);
			return $results;
		} else {
			$this->error($body, $url, null, 'GET');
		} 

	
	}

	/**
	 * Performs a put request to the instantiated class
	 * 
	 * Accepts the resource to perform the request on, and fields to be sent
	 * 
	 * @param string $resource a string to perform get on
	 * @param array $fields an array to be sent in the request
	 * @return stdClass results or var_dump error
	 */
	public function put($resource, $fields) {
			
		$url = 'https://api.bigcommerce.com/stores/' . $this->_hash . '/v2/' . $resource;
		$json = json_encode($fields);

		curl_setopt($this->_curl, CURLOPT_URL, $url);
		curl_setopt($this->_curl, CURLOPT_CUSTOMREQUEST, "PUT");
		curl_setopt($this->_curl, CURLOPT_POSTFIELDS, $json); 
		$response = curl_exec($curl);
		$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
		$headers = substr($response, 0, $header_size);
		$body = substr($response, $header_size);
		$headersArray = self::http_parse_headers($headers);
		if (! $this->rate_limit($headersArray )  && $this->retries < self::RETRY_ATTEMPTS ) {
			$this->retries = $this->retries + 1;
			return $this->put($resource, $fields);
		}
		if ($http_status == 200) {
			$results = json_decode($body);
			return $results;
		} else {
			$this->error($body, $url, $json, 'PUT');
		}

	}

	/**
	 * Performs a post request to the instantiated class
	 * 
	 * Accepts the resource to perform the request on, and fields to be sent
	 * 
	 * @param string $resource a string to perform get on
	 * @param array $fields an array to be sent in the request
	 * @return stdClass results or var_dump error
	 */
	public function post($resource, $fields) {
		global $error;
		$url = 'https://api.bigcommerce.com/stores/' . $this->_hash . '/v2/' . $resource;
		$json = json_encode($fields);

		curl_setopt($this->_curl, CURLOPT_URL, $url);
		curl_setopt($this->_curl, CURLOPT_CUSTOMREQUEST, "POST");
		curl_setopt($this->_curl, CURLOPT_POSTFIELDS, $json);
		$response = curl_exec ($curl);
		$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
		$headers = substr($response, 0, $header_size);
		$body = substr($response, $header_size);
		$headersArray = self::http_parse_headers($headers);
		if (! $this->rate_limit($headersArray)  && $this->retries < self::RETRY_ATTEMPTS ) {
			$this->retries = $this->retries + 1;
			return $this->post($resource, $fields);
		}
		if ($http_status == 201) {
			$results = json_decode($body);
			return $results;
		} else {
			$this->error($body, $url, $json, 'POST');
		}
	}

	/**
	 * Performs a delete request to the instantiated class
	 * 
	 * Accepts the resource to perform the request on
	 * 
	 * @param string $resource a string to perform get on
	 * @return string response or var_dump error
	 */
	public function delete($resource) {
			
		$url = 'https://api.bigcommerce.com/stores/' . $this->_hash . '/v2/' . $resource;
		
		curl_setopt($this->_curl, CURLOPT_URL, $url);
		curl_setopt($this->_curl, CURLOPT_CUSTOMREQUEST, "DELETE");
		$response = curl_exec($curl);
		$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
		$headers = substr($response, 0, $header_size);
		$body = substr($response, $header_size);
		$headersArray = self::http_parse_headers($headers);
		if (! $this->rate_limit($headersArray)  && $this->retries < self::RETRY_ATTEMPTS) {
			$this->retries = $this->retries + 1;
			return $this->delete($resource);
		}	        
		curl_close ($curl);
		if ($http_status == 204) {
	     	return $http_status . ' DELETED';
		 } else {
		 	$this->error($body, $url, null, 'DELETE');
		 }
	}

	/**
	 * Close curl connection
	 * 
	 * Void
	 * 
	 * @param void
	 * @return void
	 */

	public function close() {
		curl_close($this->_curl);
	}
}

?>