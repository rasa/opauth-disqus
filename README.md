Opauth-Disqus
=============
[Opauth][1] strategy for Disqus authentication.

Implemented based on url using OAuth2.

Opauth is a multi-provider authentication framework for PHP.

Demo: http://opauth.org/#disqus

Getting started
----------------
1. Install Opauth-Disqus:
   ```bash
   cd path_to_opauth/Strategy
   git clone git://github.com/rasa/opauth-disqus.git Disqus
   ```

2. Register a Disqus application at http://disqus.com/api/applications/
   - Enter URL as your application URL (this can be outside of Opauth)
   - Callback URL: enter `http://path_to_opauth/disqus/oauth2callback`

3. Under the settings tab, enter the Domains, without the scheme:
   example.com, not http://example.com

3. Configure Opauth-Disqus strategy with `api_key` and `api_secret`.

4. Direct user to `http://path_to_opauth/disqus` to authenticate

Strategy configuration
----------------------

Required parameters:

```php
<?php
'Disqus' => array(
	'api_key'    => 'YOUR API KEY',
	'api_secret' => 'YOUR API SECRET',
),
```

Optional parameters:
`scope`

License
---------
Opauth-Disqus is MIT Licensed  
Copyright (c) 2012 Ross Smith II (http://smithii.com)

[1]: https://github.com/uzyn/opauth