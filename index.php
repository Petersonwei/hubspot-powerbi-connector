<?php

/* #########################
* This code was developed by:
* Audox Ingeniería SpA.
* website: www.audox.com
* email: info@audox.com
######################### */

/**
 * Authenticates the user based on the provided headers.
 *
 * @param array $headers - The HTTP headers containing authorization information.
 * @return bool - Returns true if authentication is successful, false otherwise.
 */
function auth($headers) {
    // Convert all header keys to lowercase for consistency
    $headers = array_change_key_case($headers);

    // Check if the authorization header exists
    if (isset($headers["authorization"])) {
        // Extract the type and the token from the authorization header
        list($type, $authorization) = explode(" ", $headers["authorization"]);

        // List of valid tokens for authentication
        $valid_tokens = [
            'FREETOKEN',
            'TOKEN1',
            'TOKEN2',
        ];

        // Return true if the type is 'Bearer' and the token is in the list of valid tokens
        return ($type === "Bearer" && in_array($authorization, $valid_tokens));
    }

    // Return false if the authorization header is missing or invalid
    return false;
}

/**
 * Validates if the OAuth token is still valid based on expiration time.
 * 
 * @param array $tokenData - The token data array containing access_token, expires_in, and obtained_at
 * @return bool - Returns true if token is valid, false if expired
 */
function is_token_valid($tokenData) {
    if (empty($tokenData) || !isset($tokenData['obtained_at']) || !isset($tokenData['expires_in'])) {
        return false;
    }
    
    // Check if token is expired with 5-minute safety buffer (300 seconds)
    $currentTime = time();
    $tokenExpiryTime = $tokenData['obtained_at'] + $tokenData['expires_in'] - 300;
    
    return $currentTime < $tokenExpiryTime;
}

/**
 * Refreshes the HubSpot OAuth access token using the refresh token.
 * 
 * @param string $refresh_token - The refresh token to use for getting a new access token
 * @return array|false - Returns new token data on success, false on failure
 */
function refresh_access_token($refresh_token) {
    $clientId = getenv("HUBSPOT_CLIENT_ID");
    $clientSecret = getenv("HUBSPOT_CLIENT_SECRET");
    $redirectUri = getenv("OAUTH_REDIRECT_URI");
    
    if (!$clientId || !$clientSecret || !$redirectUri) {
        error_log("OAuth environment variables not configured for token refresh");
        return false;
    }
    
    $tokenUrl = "https://api.hubapi.com/oauth/v1/token";
    $postData = http_build_query([
        "grant_type" => "refresh_token",
        "client_id" => $clientId,
        "client_secret" => $clientSecret,
        "redirect_uri" => $redirectUri,
        "refresh_token" => $refresh_token
    ]);
    
    $ch = curl_init($tokenUrl);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/x-www-form-urlencoded"]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if (curl_errno($ch)) {
        error_log("cURL error during token refresh: " . curl_error($ch));
        curl_close($ch);
        return false;
    }
    curl_close($ch);
    
    if ($httpCode !== 200) {
        error_log("Token refresh failed with HTTP code: " . $httpCode);
        return false;
    }
    
    $data = json_decode($response, true);
    if (empty($data["access_token"])) {
        error_log("Failed to refresh access token: " . ($data["error"] ?? "unknown error"));
        return false;
    }
    
    // Return new token data with timestamp
    return [
        "access_token" => $data["access_token"],
        "refresh_token" => $data["refresh_token"] ?? $refresh_token,
        "expires_in" => $data["expires_in"] ?? 1800, // Default 30 minutes
        "obtained_at" => time()
    ];
}

/**
 * Gets a valid access token, automatically refreshing if needed.
 * 
 * @return string|false - Returns valid access token on success, false on failure
 */
function get_valid_token() {
    $oauthFile = "/tmp/hubspot_oauth.json";
    
    if (!file_exists($oauthFile)) {
        error_log("No OAuth token file found");
        return false;
    }
    
    $oauthData = json_decode(file_get_contents($oauthFile), true);
    if (empty($oauthData)) {
        error_log("Invalid OAuth token data");
        return false;
    }
    
    // Check if token is still valid
    if (is_token_valid($oauthData)) {
        return $oauthData["access_token"];
    }
    
    // Token is expired or about to expire, refresh it
    if (empty($oauthData["refresh_token"])) {
        error_log("No refresh token available");
        return false;
    }
    
    $newTokenData = refresh_access_token($oauthData["refresh_token"]);
    if ($newTokenData === false) {
        error_log("Failed to refresh token");
        return false;
    }
    
    // Save new token data
    file_put_contents($oauthFile, json_encode($newTokenData));
    
    return $newTokenData["access_token"];
}

/**
 * Fetches records from the HubSpot API based on the provided object type and parameters.
 *
 * @param string $object - The type of object to fetch (e.g., companies, contacts, deals).
 * @param array $params - Parameters to use in the API request (e.g., hapikey, filters).
 * @return array - Returns an array of records fetched from the API.
 */
function get_records($object, $params) {
    // Handle different authentication methods
    $hubspot_key = null;
    $usingOAuth = false;
    
    // Priority 1: Private App access token parameter
    if (isset($params['access_token'])) {
        $hubspot_key = $params['access_token'];
        unset($params['access_token']);
    }
    // Priority 2: Private App token from environment variable
    else if (getenv("HUBSPOT_PRIVATE_ACCESS_TOKEN")) {
        $hubspot_key = getenv("HUBSPOT_PRIVATE_ACCESS_TOKEN");
    }
    // Priority 3: Legacy API key parameter
    else if (isset($params['hapikey'])) {
        $hubspot_key = $params['hapikey'];
        unset($params['hapikey']);
    }
    // Priority 4: OAuth approach (fallback for Public Apps)
    else {
        $hubspot_key = get_valid_token();
        if ($hubspot_key === false) {
            return ["error" => "No authentication found. Please provide: access_token parameter, set HUBSPOT_PRIVATE_ACCESS_TOKEN environment variable, or complete OAuth flow."];
        }
        $usingOAuth = true;
    }

    // Base URL for the HubSpot API
    $url = 'https://api.hubapi.com/crm/v3/';

    // Special handling for OAuth token endpoint
    if ($object === 'oauth/v1/token') {
        $url = 'https://api.hubapi.com/';
        $url .= $object;
        
        // For OAuth token exchange, we need to POST the data
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/x-www-form-urlencoded'
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $output = curl_exec($ch);
        curl_close($ch);
        
        return json_decode($output, true);
    }

    // Check if the object type is one of the supported types for 'objects' endpoint
    if (in_array($object, [
        'companies', 'contacts', 'deals',
        'meetings', 'calls', 'tasks',
        'tickets',
    ])) {
        $url .= 'objects/'; // Append the 'objects/' path if the object type is supported
    }

    // Append the object type and query parameters to the URL
    $url .= $object . '?' . http_build_query($params);

    // Prepare headers for the API request, including the authorization header
    $headers = [
        'Authorization:Bearer ' . $hubspot_key,
        'Content-Type:application/json',
    ];

    // Initialize the cURL session to send the request to the API
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); // Set the headers
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // Return the response as a string

    // Execute the cURL request and get HTTP status code
    $output = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    // Handle 401 Unauthorized errors with automatic token refresh (OAuth only)
    if ($httpCode === 401 && $usingOAuth) {
        // Token likely expired, force refresh and retry once
        $oauthFile = "/tmp/hubspot_oauth.json";
        if (file_exists($oauthFile)) {
            $oauthData = json_decode(file_get_contents($oauthFile), true);
            if (!empty($oauthData["refresh_token"])) {
                $newTokenData = refresh_access_token($oauthData["refresh_token"]);
                if ($newTokenData !== false) {
                    // Save new token and retry the request
                    file_put_contents($oauthFile, json_encode($newTokenData));
                    
                    // Update the Authorization header with new token
                    $headers[0] = 'Authorization:Bearer ' . $newTokenData["access_token"];
                    
                    // Retry the request with new token
                    $ch = curl_init($url);
                    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    $output = curl_exec($ch);
                    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    curl_close($ch);
                }
            }
        }
    }

    // Decode the JSON response from the API into a PHP array
    $result = json_decode($output, true);
    
    // Handle API errors
    if ($httpCode >= 400) {
        return [
            "error" => "HubSpot API error",
            "http_code" => $httpCode,
            "response" => $result ?? $output
        ];
    }

    // Initialize an empty array to hold the records
    $records = [];

    // If the response contains results, process each record
    if (!empty($result['results'])) {
        foreach ($result['results'] as $record) {
            // For 'deals' and 'contacts', check if there are company associations
            if (in_array($object, ["deals", "contacts"]) && isset($record['associations']['companies'])) {
                $associations = $record['associations']['companies']['results'];
                foreach ($associations as $association) {
                    // Map company ID to the record if the association type matches
                    if (($object == "deals" && $association['type'] == "deal_to_company") || 
                        ($object == "contacts" && $association['type'] == "contact_to_company")) {
                        $record['properties']['company_id'] = $association['id'];
                        break; // Stop after finding the first matching association
                    }
                }
            }
            // Add the processed record to the records array
            $records[] = $record;
        }
    }

    // Handle pagination if there are more records to fetch
    if (!empty($result['paging'])) {
        // Update parameters for the next page request
        $params['hapikey'] = $hubspot_key;
        $params["after"] = $result['paging']['next']['after'];
        // Recursively fetch the next set of records and merge them with the current set
        $records = array_merge($records, get_records($object, $params));
    }

    // Return the array of records
    return $records;
}

/**
 * Main function to process the API request and return the appropriate response.
 *
 * @param array $args - Array of arguments, typically from the HTTP request.
 * @return mixed - Returns either a JSON response or prints the response based on headers.
 */
function main(array $args) {
    // Get HTTP headers from the request, either from $args or from the global request
    $headers = isset($args['http']['headers']) ? $args['http']['headers'] : getallheaders();

    // Filter parameters from the arguments, keeping only scalar values
    $params = array_filter($args, 'is_scalar');
    
    // Extract the 'action' and 'object' values from the parameters, if they exist
    foreach(['action', 'object'] as $param){
        ${$param} = isset($params[$param]) ? $params[$param] : null;
        unset($params[$param]); // Remove these from the parameters array
    }

    // Skip auth for OAuth handshake actions and token checking
    if (!in_array($action, ["authorize", "callback", "checkToken"], true)) {
        // Authorization check using the auth function
        if (function_exists('auth') && !auth($headers)) {
            $error = json_encode(["error_code" => "401", "error_description" => "Unauthorized"]);
            // Return the error response as JSON if headers are set; otherwise, print it
            return isset($args['http']['headers']) ? ["body" => $error] : print($error);
        }
    }

    // Handle different actions using switch statement
    switch ($action) {
        case "authorize":
            // 1) Redirect user to HubSpot consent screen
            $clientId = getenv("HUBSPOT_CLIENT_ID");
            $redirect = urlencode(getenv("OAUTH_REDIRECT_URI"));
            
            // Get scopes from environment variable or use default
            $envScopes = getenv("OAUTH_SCOPES");
            if ($envScopes) {
                $scopes = $envScopes;
            } else {
                // Default scopes matching your HubSpot app configuration
                $scopes = implode(" ", [
                    "crm.objects.companies.read",
                    "crm.objects.contacts.read", 
                    "crm.objects.deals.read",
                    "crm.objects.owners.read",
                    "oauth"
                ]);
            }
            
            if (!$clientId || !$redirect) {
                $result = json_encode(["error" => "OAuth environment variables not configured"]);
                break;
            }
            
            $authUrl = "https://app.hubspot.com/oauth/authorize"
                     . "?client_id={$clientId}"
                     . "&scope=" . urlencode($scopes)
                     . "&redirect_uri={$redirect}";
            
            // Return redirect URL in response if headers are set (API call)
            if (isset($args['http']['headers'])) {
                $result = json_encode([
                    "redirect_url" => $authUrl,
                    "scopes_used" => $scopes,
                    "scopes_source" => $envScopes ? "environment" : "default"
                ]);
            } else {
                // Direct browser access - redirect immediately
                header("Location: " . $authUrl);
                exit;
            }
            break;

        case "callback":
            // 2) Exchange code for access token
            if (!isset($_GET["code"])) {
                exit("Error: no code provided");
            }
            
            $code = $_GET["code"];
            $clientId = getenv("HUBSPOT_CLIENT_ID");
            $secret = getenv("HUBSPOT_CLIENT_SECRET");
            $redirect = getenv("OAUTH_REDIRECT_URI");
            
            if (!$clientId || !$secret || !$redirect) {
                exit("Error: OAuth environment variables not configured");
            }
            
            // 2) Exchange code for tokens
            $tokenUrl = "https://api.hubapi.com/oauth/v1/token";
            $postData = http_build_query([
                "grant_type"    => "authorization_code",
                "client_id"     => $clientId,
                "client_secret" => $secret,
                "redirect_uri"  => $redirect,
                "code"          => $code
            ]);

            $ch = curl_init($tokenUrl);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/x-www-form-urlencoded"]);
            $response = curl_exec($ch);
            if (curl_errno($ch)) {
                exit("cURL error: " . curl_error($ch));
            }
            curl_close($ch);

            $data = json_decode($response, true);
            if (empty($data["access_token"])) {
                exit("Failed to obtain access token: " . ($data["error"] ?? "unknown error"));
            }

            // 3) Persist tokens securely
            // Here we write to /tmp; in production use a database or secret store
            file_put_contents("/tmp/hubspot_oauth.json", json_encode([
                "access_token"  => $data["access_token"],
                "refresh_token" => $data["refresh_token"] ?? null,
                "expires_in"    => $data["expires_in"] ?? null,
                "obtained_at"   => time()
            ]));

            echo "OAuth setup complete. You can now close this window.";
            exit;

        case "getRecords":
            // Original getRecords functionality
            if (isset($params['properties']) && $params['properties'] === "*") {
                $properties = get_records("properties/{$object}", $params);
                $params['properties'] = implode(",", array_column($properties, 'name'));
            }
            // Fetch records based on the object and parameters, and convert to JSON
            $result = json_encode(get_records($object, $params));
            break;

        case "checkToken":
            // Check authentication status for all methods
            $authStatus = [
                "timestamp" => date('Y-m-d H:i:s'),
                "methods_checked" => []
            ];
            
            // Check Private App access token parameter
            if (isset($params['access_token'])) {
                $authStatus["methods_checked"][] = "access_token_parameter";
                $authStatus["auth_method"] = "Private App (parameter)";
                $authStatus["valid"] = true;
                $authStatus["token_type"] = "Private App Access Token";
                $authStatus["expires"] = "Never (Private App tokens are permanent)";
            }
            // Check environment variable
            else if (getenv("HUBSPOT_PRIVATE_ACCESS_TOKEN")) {
                $authStatus["methods_checked"][] = "environment_variable";
                $authStatus["auth_method"] = "Private App (environment)";
                $authStatus["valid"] = true;
                $authStatus["token_type"] = "Private App Access Token";
                $authStatus["expires"] = "Never (Private App tokens are permanent)";
                $authStatus["env_var_set"] = true;
            }
            // Check OAuth token
            else {
                $oauthFile = "/tmp/hubspot_oauth.json";
                $authStatus["methods_checked"][] = "oauth_file";
                
                if (!file_exists($oauthFile)) {
                    $authStatus["valid"] = false;
                    $authStatus["error"] = "No authentication found";
                    $authStatus["suggestions"] = [
                        "Set HUBSPOT_PRIVATE_ACCESS_TOKEN environment variable",
                        "Pass access_token parameter",
                        "Complete OAuth flow for Public Apps"
                    ];
                } else {
                    $oauthData = json_decode(file_get_contents($oauthFile), true);
                    if (empty($oauthData)) {
                        $authStatus["valid"] = false;
                        $authStatus["error"] = "Invalid OAuth token data";
                    } else {
                        $isValid = is_token_valid($oauthData);
                        $hasRefreshToken = !empty($oauthData["refresh_token"]);
                        
                        $authStatus["valid"] = $isValid;
                        $authStatus["auth_method"] = "OAuth (Public App)";
                        $authStatus["has_refresh_token"] = $hasRefreshToken;
                        $authStatus["expires_in"] = isset($oauthData["expires_in"]) ? $oauthData["expires_in"] : null;
                        
                        if (isset($oauthData["obtained_at"]) && isset($oauthData["expires_in"])) {
                            $expiresAt = $oauthData["obtained_at"] + $oauthData["expires_in"];
                            $authStatus["expires_at"] = date('Y-m-d H:i:s', $expiresAt);
                            $authStatus["seconds_until_expiry"] = max(0, $expiresAt - time());
                        }
                    }
                }
            }
            
            $result = json_encode($authStatus, JSON_PRETTY_PRINT);
            break;

        default:
            // If the action is invalid, return an error response
            $result = json_encode(["error" => "Invalid action. Supported actions: authorize, callback, getRecords, checkToken"]);
            break;
    }

    // Return the JSON response if headers are set; otherwise, print it
    return isset($args['http']['headers']) ? ["body" => $result] : print($result);
}

header('Content-Type: application/json');
http_response_code(200);

// Call the main function with the request arguments ($_REQUEST) as input
main($_REQUEST);

?>