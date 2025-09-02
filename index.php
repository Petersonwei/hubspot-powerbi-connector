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
 * Fetches records from the HubSpot API based on the provided object type and parameters.
 *
 * @param string $object - The type of object to fetch (e.g., companies, contacts, deals).
 * @param array $params - Parameters to use in the API request (e.g., hapikey, filters).
 * @return array - Returns an array of records fetched from the API.
 */
function get_records($object, $params) {
    // Handle OAuth token vs API key
    $hubspot_key = null;
    if (isset($params['hapikey'])) {
        // Traditional API key approach
        $hubspot_key = $params['hapikey'];
        unset($params['hapikey']);
    } else {
        // OAuth approach - read token from storage
        $oauthFile = "/tmp/hubspot_oauth.json";
        if (!file_exists($oauthFile)) {
            return ["error" => "No OAuth token found. Please complete OAuth flow first."];
        }
        $oauthData = json_decode(file_get_contents($oauthFile), true);
        if (empty($oauthData["access_token"])) {
            return ["error" => "Invalid OAuth token data. Please complete OAuth flow again."];
        }
        $hubspot_key = $oauthData["access_token"];
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

    // Execute the cURL request and close the session
    $output = curl_exec($ch);
    curl_close($ch);

    // Decode the JSON response from the API into a PHP array
    $result = json_decode($output, true);

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

    // Skip auth for OAuth handshake actions
    if (!in_array($action, ["authorize", "callback"], true)) {
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

        default:
            // If the action is invalid, return an error response
            $result = json_encode(["error" => "Invalid action. Supported actions: authorize, callback, getRecords"]);
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