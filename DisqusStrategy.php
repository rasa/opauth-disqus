<?php
/**
 * Disqus strategy for Opauth
 * 
 * More information on Opauth: http://opauth.org
 * 
 * @copyright    Copyright (c) 2012  Ross Smith II (http://smithii.com)
 * @link         http://opauth.org
 * @package      Opauth.DisqusStrategy
 * @license      MIT License
 */

/**
 * Disqus strategy for Opauth
 * 
 * @package         Opauth.Disqus
 */
class DisqusStrategy extends OpauthStrategy {
    
    /**
     * Compulsory config keys, listed as unassociative arrays
     */
    public $expects = array('api_key', 'api_secret');
    
    /**
     * Optional config keys, without predefining any default values.
     */
    public $optionals = array('redirect_uri', 'scope');
    
    /**
     * Optional config keys with respective default values, listed as associative arrays
     * eg. array('scope' => 'email');
     */
    public $defaults = array(
        'redirect_uri' => '{complete_url_to_strategy}oauth2callback',
        #'scope' => 'read', # read,write is the default, so let's keep it that way
    );
    
    /**
     * Auth request
     */
    public function request() {
        $url = 'https://disqus.com/api/oauth/2.0/authorize/';
        $params = array(
            'client_id' => $this->strategy['api_key'],
            'redirect_uri' => $this->strategy['redirect_uri'],
            'response_type' => 'code',
        );

        foreach ($this->optionals as $key) {
            if (!empty($this->strategy[$key])) $params[$key] = $this->strategy[$key];
        }

        $this->clientGet($url, $params);
    }
    
    /**
     * Internal callback, after OAuth
     */
    public function oauth2callback() {
        if (array_key_exists('code', $_GET) && !empty($_GET['code'])) {
            $code = $_GET['code'];
            $url = 'https://disqus.com/api/oauth/2.0/access_token/';
            
            $params = array(
                'code' => $code,
                'client_id' => $this->strategy['api_key'],
                'client_secret' => $this->strategy['api_secret'],
                'redirect_uri' => $this->strategy['redirect_uri'],
                'grant_type' => 'authorization_code',
            );
            if (!empty($this->strategy['state'])) $params['state'] = $this->strategy['state'];
            $response = $this->serverPost($url, $params, null, $headers);
            $results = $this->recursiveGetObjectVars(json_decode($response));
           
            if (!empty($results) && !empty($results['access_token'])) {
                $user = $this->user($results['access_token']);
                $response = $user['response'];
                $this->auth = array(
                    'uid' => $results['user_id'],
                    'info' => array(
                    ),
                    'credentials' => array(
                        'token' => $results['access_token'],
                        'expires' => date('c', time() + $results['expires_in']),
                    ),
                    'raw' => array('results' => $results, 'user' => $user),
                );

                $this->mapProfile($response, 'name', 'info.name');
                #$this->mapProfile($response, 'blog', 'info.urls.blog');
                $this->mapProfile($response, 'avatar.permalink', 'info.image');
                $this->mapProfile($response, 'about', 'info.description');
                $this->mapProfile($results, 'username', 'info.username');
                $this->mapProfile($response, 'url', 'info.urls.url');
                #$this->mapProfile($response, 'email', 'info.email');
                $this->mapProfile($response, 'location', 'info.location');
                $this->mapProfile($response, 'profileUrl', 'info.urls.profile');

                $this->callback();
            }
            else {
                $error = array(
                    'code' => 'access_token_error',
                    'message' => 'Failed when attempting to obtain access token',
                    'raw' => array(
                        'response' => $response,
                        'headers' => $headers,
                    )
                );

                $this->errorCallback($error);
            }
        }
        else {
            $error = array(
                'code' => 'oauth2callback_error',
                'raw' => $_GET,
            );
            
            $this->errorCallback($error);
        }
    }

    /**
     * Queries Disqus v3 API for user info
     *
     * @param string $access_token 
     * @return array Parsed JSON results
     */
    private function user($access_token) {
        $params = array(
            'access_token' => $access_token,
            'api_key' => $this->strategy['api_key'],
            #'api_secret' => $this->strategy['api_secret'], # not required
        );
       
        $user = $this->serverGet('https://disqus.com/api/3.0/users/details.json', $params, null, $headers);

        if (!empty($user)) {
            return $this->recursiveGetObjectVars(json_decode($user));
        }
        else {
            $error = array(
                'code' => 'userinfo_error',
                'message' => 'Failed when attempting to query Disqus v3 API for user information',
                'raw' => array(
                    'response' => $user,
                    'headers' => $headers
                )
            );

            $this->errorCallback($error);
        }
    }
}
