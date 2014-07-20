ITS-Bigcommerce-API
================================
Library for connecting to the OAuth Bigcommerce API. (IntuitSolutions')[http://www.intuitsolutions.net] fork of (PHP-cURL-lib-for-Bigcommerce-API) [https://github.com/adambilsing/PHP-cURL-lib-for-Bigcommerce-API] by Adam Bilsing, authored by Than Hedman.

Require the file in your script as follows:
```
require 'connection.php';
```
Instantiate connection class as such:
```
$store = new connection('Client ID', 'Store Hash', 'Access Token');
```
call various methods to the connection

```
$store->get('RESOURCE', $filter = null);

$store->delete('RESOURCE');

$store->post('RESOURCE', $fields);

$store->put('RESOURCE', $fields);
```

If the request fails the error details will be stored in the $error var.

If the rate limit is reached, the function will sleep for the retry-after time, then retry.
