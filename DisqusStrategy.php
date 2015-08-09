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
    const AUTH_URL = 'https://disqus.com/api/oauth/2.0/authorize/';

    const ACCESS_URL = 'https://disqus.com/api/oauth/2.0/access_token/';

    const USER_URL = 'https://disqus.com/api/3.0/users/details.json';
    
    const STRATEGY = 'Disqus';

    const ERROR_ACCESS_TOKEN = 'Failed to obtain access token';

    const ERROR_USER_INFO = 'Failed to obtain user information';
    
    /**
     * Compulsory config keys, listed as unassociative arrays
     */
    public $expects = array(
        'api_key', 
        'api_secret',
    );
    
    /**
     * Optional config keys, without predefining any default values.
     */
    public $optionals = array(
        'redirect_uri',
        'scope',
    );
    
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
        $params = array(
            'client_id' => $this->strategy['api_key'],
            'redirect_uri' => $this->strategy['redirect_uri'],
            'response_type' => 'code',
        );

        foreach ($this->optionals as $key) {
            if (!empty($this->strategy[$key])) {
                $params[$key] = $this->strategy[$key];
            }
        }

        $this->clientGet(self::AUTH_URL, $params);
    }
    
    /**
     * Internal callback, after OAuth
     */
    public function oauth2callback() {
        if (!array_key_exists('code', $_GET) || empty($_GET['code'])) {
            $error = array(
                'code' => 'oauth2callback_error',
                'raw' => $_GET,
            );
            
            $this->errorCallback($error);
            return;
        }

        $code = $_GET['code'];

        $params = array(
            'code' => $code,
            'client_id' => $this->strategy['api_key'],
            'client_secret' => $this->strategy['api_secret'],
            'redirect_uri' => $this->strategy['redirect_uri'],
            'grant_type' => 'authorization_code',
        );
        if (!empty($this->strategy['state'])) {
            $params['state'] = $this->strategy['state'];
        }
        
        $response = $this->serverPost(self::ACCESS_URL, $params, null, $headers);

        $results = $this->recursiveGetObjectVars(json_decode($response));

        if (empty($results) || empty($results['access_token'])) {
            $errno = 1;
            $msg = sprintf('%s: %s (%s)', self::STRATEGY, self::ERROR_ACCESS_TOKEN, $errno);

            $error = array(
                'code' => 'access_token_error',
                'message' => self::ERROR_ACCESS_TOKEN,
                'raw' => array(
                    'response' => $response,
                    'headers' => $headers,
                )
            );

            $this->errorCallback($error);
            return;
        }

        $response = $this->user($results['access_token']);
        if (!$response) {
            return;
        }

        $auth = array(
            'uid' => $results['user_id'],
            'info' => array(
            ),
            'credentials' => array(
                'token' => $results['access_token'],
            ),
            'raw' => array(
                'results' => $results,
                'user' => $response,
            ),
        );

        if (isset($results['expires_in'])) {
            $auth['credentials']['expires'] = date('c', time() + $results['expires_in']);
        }
        
        $this->auth = $auth;

        $this->mapProfile($response, 'name', 'info.name');
        #$this->mapProfile($response, 'blog', 'info.urls.blog');
        $this->mapProfile($response, 'avatar.permalink', 'info.image');
        $this->mapProfile($response, 'about', 'info.description');
        $this->mapProfile($results, 'username', 'info.username');
        $this->mapProfile($response, 'url', 'info.urls.url');
        $this->mapProfile($response, 'email', 'info.email');
        $this->mapProfile($response, 'location', 'info.location');
        $this->mapProfile($response, 'profileUrl', 'info.urls.profile');

        $this->callback();
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
       
        $user = $this->serverGet(self::USER_URL, $params, null, $headers);

        while (true) {
            if (empty($user)) {
                $errno = 2;
                break;
            }
            $rv = $this->recursiveGetObjectVars(json_decode($user));
            if (empty($rv)) {
                $errno = 5;
                break;
            }
            if (!isset($rv['code'])) {
                $errno = 3;
                break;
            }

            if ($rv['code'] <> 0) {
                $errno = 4;
                break;
            }

            if (!isset($rv['response'])) {
                $errno = 6;
                break;
            }
            return $rv['response'];
        }

        $msg = sprintf('%s: %s (%s)', self::STRATEGY, self::ERROR_USER_INFO, $errno);
        
        $error = array(
            'code' => 'userinfo_error',
            'message' => $msg,
            'raw' => array(
                'response' => $user,
                'headers' => $headers,
            )
        );

        $this->errorCallback($error);
        
        return null;
    }
}
