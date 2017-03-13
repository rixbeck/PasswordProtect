<?php

namespace Bolt\Extension\Bolt\PasswordProtect\Handler;

use Bolt\Storage;
use GuzzleHttp\Exception\RequestException;
use Silex\Application;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Twig_Markup;

class Checker
{

    /** @var Request $request */
    protected $request;

    /** @var array $config */
    protected $config;

    /** @var Session $session */
    protected $session;

    /** @var Storage $storage */
    protected $storage;

    /** @var Application $app */
    protected $app;

    public function __construct(
        Application $app,
        array $config
    )
    {
        $this->app = $app;
        $this->config = $config;
    }

    /**
     * Check the content type of the request to see if it is password protected.
     *
     * @param Request $request
     */
    public function checkContentTypeOnRequest(Request $request)
    {
        //get the path, typically /members-only/home
        $path = $request->get('contenttypeslug');

        //Grab key 1 that has members-only
        if ($path !== null) {
            $contenttype = (array) $this->config['contenttype'];

            //Check if members-only is the same contenttype in our config file
            if (in_array($path, $contenttype)) {
                $this->checkSessionAndRedirect();
            }
        }

    }

    /**
     * Check if we're currently allowed to view the page. If not, redirect to
     * the password page.
     *
     * @return \Twig_Markup
     */
    public function passwordProtect()
    {
        $this->checkSessionAndRedirect();
    }

    /**
     * Check if users can be logged on.
     *
     * @return boolean
     */
    public function checkLogin($data)
    {

        if (empty($data['password'])) {
            return false;
        }

        if ($this->config['authenticators']) {
            $authenticators = (array) $this->config['authenticators'];
            $token = new UsernamePasswordToken($data['username'], $data['password'], 'PasswordProtect', ['visitor']);
            $extensions = $this->app['extensions']->all();
            foreach ($authenticators as $providerExtensionId=>$providerId) {
                if (array_key_exists($providerExtensionId, $extensions) && $this->app->offsetExists($providerId)) {
                    $provider = $this->app[$providerId];
                    /** @var AuthenticationProviderInterface $provider */
                    if ($provider instanceof AuthenticationProviderInterface) {
                        try {
                            $provider->authenticate($token);

                            return $token->getUser();
                        } catch (AuthenticationException $e) {

                            return false;
                        } catch (RequestException $e) {

                            return false;
                        }

                    }
                }
                else {
                    // @todo Try to log 'No authprovider NNN found'
                }
            }
        }
        // If we only use the password, the 'users' array is just one element.
        if ($this->config['password_only']) {
            $visitors = array('visitor' => $this->config['password']);
            $data['username'] = 'visitor';
        } else {
            $visitors = $this->config['visitors'];
        }

        foreach ($visitors as $visitor => $password) {
            if ($data['username'] === $visitor) {
                // echo "user match!";
                if (($this->config['encryption'] == 'md5') && (md5($data['password']) === $password)) {
                    return $visitor;
                } elseif (($this->config['encryption'] == 'password_hash') && password_verify($data['password'], $password)) {
                    return $visitor;
                } elseif (($this->config['encryption'] == 'plaintext') && ($data['password'] === $password)) {
                    return $visitor;
                }
            }
        }

        // If we get here, no dice.
        return false;

    }

    /**
     * Function to check if session is set, otherwise redirect and login
     *
     * @return \Twig_Markup
     */
    protected function checkSessionAndRedirect()
    {
        if ($this->app['session']->get('passwordprotect') == 1) {
            return new Twig_Markup("<!-- Password protection OK! -->", 'UTF-8');
        } else {
            $redirectto = $this->app['storage']->getContent($this->config['redirect'], ['returnsingle' => true]);
            $returnto = $this->app['request_stack']->getCurrentRequest()->getRequestUri();
            if ($redirectto === false) {
                $linkTo = $this->config['redirect'];
            } else {
                $linkTo = $redirectto->link();
            }
            $response = new RedirectResponse($linkTo."?returnto=".urlencode($returnto));
            $response->send();
            die();
        }
    }
}
