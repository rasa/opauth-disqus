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
        'scope' => 'read',
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
            $results = json_decode($response, true);
           
            if (!empty($results) && !empty($results['access_token'])) {
                $this->auth = array(
                    'uid' => $results['user_id'],
                    'info' => array(
                        'nickname' => $results['username'],
                    ),
                    'credentials' => array(
                        'token' => $results['access_token']
                    ),
                    'raw' => $results
                );
                #$this->mapProfile($results, 'name', 'username'); # doesn't work?
                $this->callback();
            }
            else {
                $error = array(
                    'code' => 'access_token_error',
                    'message' => 'Failed when attempting to obtain access token',
                    'raw' => array(
                        'response' => $response,
                        'headers' => $headers
                    )
                );

                $this->errorCallback($error);
            }
        }
        else {
            $error = array(
                'code' => 'oauth2callback_error',
                'raw' => $_GET
            );
            
            $this->errorCallback($error);
        }
    }
}
