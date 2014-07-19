<?php
/**
 *Class to instantiate different api connections
 * 
 * @author Adam Bilsing <adambilsing@gmail.com>
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


	/**
	 * Sets $_hash, $_client, $_token, $_headers upon class instantiation
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
		curl_close ($ch);
		$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		if ($http_status == 200) {
			$results = json_decode($response);
			return $results;
		} else {
			return false;
		}
	}


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

    public function rate_limit( $headers )
    {
    	if ($headers['X-Retry-After'] > 0) {
        	sleep($headers['X-Retry-After']);
        }
    }

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
	 * @return results or var_dump error
	 */
	public function get($resource) {

		$url = 'https://api.bigcommerce.com/stores/' . $this->_hash . '/v2/' . $resource;

		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_HTTPHEADER, $this->_headers);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($curl, CURLOPT_VERBOSE, 1);
		curl_setopt($curl, CURLOPT_HEADER, 1);
		curl_setopt($curl, CURLOPT_HTTPGET, 1);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);            
		$response = curl_exec($curl);
		$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
		$headers = substr($response, 0, $header_size);
		$body = substr($response, $header_size);
		$headersArray = self::http_parse_headers($headers);
		$this->rate_limit($headersArray);
		curl_close ($curl);
		if ($http_status == 200) {
			$results = json_decode($body, true);
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
	 * @return results or var_dump error
	 */
	public function put($resource, $fields) {
			
		$url = 'https://api.bigcommerce.com/stores/' . $this->_hash . '/v2/' . $resource;
		$json = json_encode($fields);
		
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_HTTPHEADER, $this->_headers);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_VERBOSE, 1);
		curl_setopt($curl, CURLOPT_HEADER, 1);
		curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "PUT");
		curl_setopt($curl, CURLOPT_POSTFIELDS, $json); 
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		$response = curl_exec($curl);
		$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
		$headers = substr($response, 0, $header_size);
		$body = substr($response, $header_size);
		$headersArray = self::http_parse_headers($headers);
		$this->rate_limit($headersArray);
		curl_close($curl);
		if ($http_status == 200) {
			$results = json_decode($body, true);
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
	 * @return results or var_dump error
	 */
	public function post($resource, $fields) {
		global $error;
		$url = 'https://api.bigcommerce.com/stores/' . $this->_hash . '/v2/' . $resource;
		$json = json_encode($fields);

		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_HTTPHEADER, $this->_headers);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_VERBOSE, 1);
		curl_setopt($curl, CURLOPT_HEADER, 1);
		curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
		curl_setopt($curl, CURLOPT_POSTFIELDS, $json);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		$response = curl_exec ($curl);
		$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
		$headers = substr($response, 0, $header_size);
		$body = substr($response, $header_size);
		$headersArray = self::http_parse_headers($headers);
		$this->rate_limit($headersArray);
		curl_close ($curl);
		if ($http_status == 201) {
			$results = json_decode($body, true);
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
	 * @return proper response or var_dump error
	 */
	public function delete($resource) {
			
		$url = 'https://api.bigcommerce.com/stores/' . $this->_hash . '/v2/' . $resource;
		
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_HTTPHEADER, $this->_headers);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_VERBOSE, 1);
		curl_setopt($curl, CURLOPT_HEADER, 1);
		curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "DELETE");
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		$response = curl_exec($curl);
		$http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
		$headers = substr($response, 0, $header_size);
		$body = substr($response, $header_size);
		$headersArray = self::http_parse_headers($headers);
		$this->rate_limit($headersArray);	        
		curl_close ($curl);
		if ($http_status == 204) {
	     	return $http_status . ' DELETED';
		 } else {
		 	$this->error($body, $url, null, 'DELETE');
		 }
	}
}

?>