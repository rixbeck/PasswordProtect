<?php
// PasswordProtect Extension for Bolt

namespace Bolt\Extension\Bolt\PasswordProtect;

use Hautelook\Phpass\PasswordHash;
use Bolt\Library as Lib;

class Extension extends \Bolt\BaseExtension
{
    public function getName()
    {
        return "Password Protect";
    }

    public function initialize()
    {

        if (empty($this->config['encryption'])) {
            $this->config['encryption'] = "plaintext";
        }

        $this->addTwigFunction('passwordprotect', 'passwordProtect');
        $this->addTwigFunction('passwordform', 'passwordForm');

        $path = $this->app['config']->get('general/branding/path') . '/generatepasswords';
        $this->app->match($path, array($this, "generatepasswords"));

        $extension = $this;

        // Register this extension's actions as an early event.
        $this->app->before(function (Request $request) use ($extension) {
            return $extension->checkContentTypeOnRequest($request);
        }, SilexApplication::EARLY_EVENT);

    }

    /**
     * Check the content type of the request to see if it is password protected.
     *
     * @param Request $request
     */
    public function checkContentTypeOnRequest(Request $request)
    {
        #get the path, typically /members-only/home
        $path = explode("/", $request->getPathInfo());

        //Grab key 1 that has members-only
        if (isset($path[1])) {
            //Check if members-only is the same contentType in our config file
            if ($path[1] === $this->config['contentType']) {
                $this->checkSessionAndRedirect();
            }
        }

    }

    /**
     * Function to check if session is set, otherwise redirect and login
     *
     * @return \Twig_Markup
     */
    protected function checkSessionAndRedirect()
    {
        if ($this->app['session']->get('passwordprotect') == 1) {
            return new \Twig_Markup("<!-- Password protection OK! -->", 'UTF-8');
        } else {
            $redirectto = $this->app['storage']->getContent($this->config['redirect'], array('returnsingle' => true));
            $returnto = $this->app['request']->getRequestUri();
            $redirect = Lib::simpleredirect($redirectto->link(). "?returnto=" . urlencode($returnto));

            // Yeah, this isn't very nice, but we _do_ want to shortcircuit the request.
            die();
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
     * Show the password form. If the visitor gives the correct password, they
     * are redirected to the page they came from, if any.
     *
     * @return \Twig_Markup
     */
    public function passwordForm()
    {

        // Set up the form.
        $form = $this->app['form.factory']->createBuilder('form');

        if ($this->config['password_only'] == false) {
            $form->add('username', 'text');
        }

        $form->add('password', 'password');
        $form = $form->getForm();

        if ($this->app['request']->getMethod() == 'POST') {

            $form->bind($this->app['request']);

            $data = $form->getData();

            if ($form->isValid() && $this->checkLogin($data)) {

                // Set the session var, so we're authenticated..
                $this->app['session']->set('passwordprotect', 1);
                $this->app['session']->set('passwordprotect_name', $this->checkLogin($data));

                // Print a friendly message..
                printf("<p class='message-correct'>%s</p>", $this->config['message_correct']);

                $returnto = $this->app['request']->get('returnto');

                // And back we go, to the page we originally came from..
                if (!empty($returnto)) {
                    Lib::simpleredirect($returnto);
                    die();
                }

            } else {

                // Remove the session var, so we can test 'logging off'..
                $this->app['session']->remove('passwordprotect');
                $this->app['session']->remove('passwordprotect_name');

                // Print a friendly message..
                if(!empty($data['password'])) {
                    printf("<p class='message-wrong'>%s</p>", $this->config['message_wrong']);
                }

            }

        }

        // Render the form, and show it it the visitor.
        $this->app['twig.loader.filesystem']->addPath(__DIR__);
        $html = $this->app['twig']->render('assets/passwordform.twig', array('form' => $form->createView()));

        return new \Twig_Markup($html, 'UTF-8');

    }

    /**
     * Allow users to place {{ passwordprotect() }} tags into content, if
     * `allowtwig: true` is set in the contenttype.
     *
     * @return boolean
     */
    public function isSafe()
    {
        return true;
    }

    /**
     * Check if users can be logged on.
     *
     * @return boolean
     */
    private function checkLogin($data)
    {

        if (empty($data['password'])) {
            return false;
        }

        $hasher = new PasswordHash(12, true);

        // dump($this->config);

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
                } elseif (($this->config['encryption'] == 'password_hash') && $hasher->CheckPassword($data['password'], $password)) {
                    return $visitor;
                } elseif (($this->config['encryption'] == 'plaintext') && ($data['password'] === $password))  {
                    return $visitor;
                }
            }
        }

        // If we get here, no dice.
        return false;

    }


    public function generatepasswords()
    {

        if (!$this->app['users']->isAllowed('dashboard')) {
            die('You do not have the right privileges to view this page.');
        }

        // Set up the form.
        $form = $this->app['form.factory']->createBuilder('form');
        $form->add('password', 'text');
        $form = $form->getForm();

        $password = false;

        if ($this->app['request']->getMethod() == 'POST') {
            $form->bind($this->app['request']);
            $data = $form->getData();
            if ($form->isValid()) {
                $hasher = new PasswordHash(12, true);
                $password = $hasher->HashPassword($data['password']);
            }
        }

        // Render the form, and show it it the visitor.
        $this->app['twig.loader.filesystem']->addPath(__DIR__);
        $html = $this->app['twig']->render('assets/passwordgenerate.twig', array('form' => $form->createView(), 'password' => $password));

        return new \Twig_Markup($html, 'UTF-8');

    }

}
