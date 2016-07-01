<?php

/**
 * Roundcube Webmail Login Security plugin
 *
 * @author Drew Phillips <dapphp@sonic.net>
 * @copyright 2016 Sonic.net, Inc.
 * @license BSD-3-Clause
 * @version 1.0.0 (June 16th, 2016)
 *
 */

class login_security extends rcube_plugin
{
    /** @var string  The name of this plugin */
    const NAME = 'login_security';

    /** @var int  Maximum number of recovery codes to allow */
    const NUM_RECOVERY_CODES = 6;

    /** @var rcmail  Application class of Roundcube Webmail */
    protected $rc;

    /** @var stdClass  Object holding plugin specific configuration */
    protected $cfg;

    /** @var string  The client IP address */
    protected $ip;

    /** @var bool  Whether this IP is banned or not */
    protected $banned;

    /**
     * Plugin init method - prepares the plugin for execution
     *
     * @return void
     */
    public function init()
    {
        $this->rc  = rcmail::get_instance();
        $this->ip  = rcube_utils::remote_addr();
        $this->cfg = new stdClass();

        $this->add_texts('localization/');
        $this->load_config();

        // store plugin specific config options locally
        $this->cfg->logsec_use_captcha        = $this->rc->config->get('logsec_use_captcha', false);
        $this->cfg->logsec_use_captcha_audio  = $this->rc->config->get('logsec_use_captcha_audio', false);
        $this->cfg->logsec_captcha_threshold  = $this->rc->config->get('logsec_captcha_threshold', 5);
        $this->cfg->logsec_ban_attempts       = $this->rc->config->get('logsec_ban_attempts', 15);
        $this->cfg->logsec_ban_threshold      = $this->rc->config->get('logsec_ban_threshold', 15);
        $this->cfg->logsec_ban_time           = $this->rc->config->get('logsec_ban_time', 5);
        $this->cfg->logsec_otp_enabled        = $this->rc->config->get('logsec_otp_enabled', true);
        $this->cfg->logsec_captcha_appearance = $this->rc->config->get('logsec_captcha_appearance', array());

        $this->add_hook('startup', array($this, 'startup'));
        $this->add_hook('ready',   array($this, 'ready'));

        if ($this->rc->task == 'login') {
            // hooks to register when task=_login
            $this->add_hook('template_object_loginform', array($this, 'login'));
            $this->add_hook('authenticate', array($this, 'checkLogin'));
            $this->add_hook('login_after',  array($this, 'loginAfter'));
            $this->add_hook('login_failed', array($this, 'loginFailed'));
        } elseif ($this->rc->task == 'settings') {
            // hooks to register when task=_settings
            $this->add_hook('preferences_list',          array($this, 'preferencesList'));
            $this->add_hook('preferences_sections_list', array($this, 'preferencesSection'));
            $this->add_hook('preferences_save',          array($this, 'preferencesSave'));
        }
    }

    /**
     * Plugin startup routine (after Roundcube initializes).
     * This function is used to display or validate captcha prior to login if used
     *
     * @param array $params  task and action
     * @return array
     */
    public function startup($params)
    {
        $this->gc(); // clear up old failed logins

        if ($params['action'] == 'logsec_captcha') {
            // action to display the captcha and bail
            // since we're displaying through RC, session data for captcha & validation go through RC's session handler

            if (!$this->cfg->logsec_use_captcha || $this->getFailedLoginCount() < $this->cfg->logsec_captcha_threshold) {
                // don't generate captcha unless necessary
                exit;
            }

            $defaults = array(
                'charset'              => 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghkmnpqrstuvwxyz23456789',
                'perturbation'         => .85,
                'code_length'          => 6,
                'use_transparent_text' => false,
                'num_lines'            => 4,
            );

            if (!is_array($this->cfg->logsec_captcha_appearance)) {
                $this->cfg->logsec_captcha_appearance = array();
            }

            $opts = array_merge($defaults, $this->cfg->logsec_captcha_appearance);

            $opts['namespace'] = 'roundcube_logsec';

            $img = new Securimage($opts);

            $img->show();
            exit;
        } elseif ($params['action'] == 'logsec_captcha_audio') {
            // play captcha audio and bail
            // since we're playing through RC, audio playback is based on code in RC's session

            if (
                !$this->cfg->logsec_use_captcha ||
                !$this->cfg->logsec_use_captcha_audio ||
                $this->getFailedLoginCount() < $this->cfg->logsec_captcha_threshold
            ) {
                // don't generate captcha audio unless necessary
                exit;
            }

            $img = new Securimage(array('namespace' => 'roundcube_logsec'));
            $img->outputAudioFile('wav');
            exit;
        } elseif ($params['task'] == 'login' && $params['action'] == 'login') {
            // a login post request - check if captcha enabled and should be checked
            if ($this->cfg->logsec_use_captcha == true) {
                $failures = $this->getFailedLoginCount();

                if ($failures >= $this->cfg->logsec_captcha_threshold) {
                    $img  = new Securimage(array('namespace' => 'roundcube_logsec'));
                    $code = $_POST['login_security_code'];

                    $this->captcha_passed = $img->check($code);
                }
            }
        }

        return $params;
    }

    /**
     * Login handler - injects captcha into login form if required
     *
     * @param array $form  Login form content array
     * @return array
     */
    public function login($form)
    {
        $failures = $this->getFailedLoginCount();

        if ($this->cfg->logsec_use_captcha && $failures >= $this->cfg->logsec_captcha_threshold) {
            $this->rc->output->add_header("<style type='text/css'>\n#login-form .box-inner { background-size: cover; }\n</style>");

            $opts = array(
                'securimage_path' => 'vendor/dapphp/securimage',
                'show_image_url'  => $this->rc->url(array('action' => 'logsec_captcha')),
                'audio_play_url'  => $this->rc->url(array('action' => 'logsec_captcha_audio')),
                'input_text'      => $this->gettext('entercode'),
                'input_name'      => 'login_security_code',
            );

            $captcha  = '<tr><td></td><td class="input">' .
                        Securimage::getCaptchaHtml($opts, Securimage::HTML_IMG);
            if ($this->cfg->logsec_use_captcha_audio) {
                $captcha .= Securimage::getCaptchaHtml($opts, Securimage::HTML_AUDIO);
            }
            $captcha .= Securimage::getCaptchaHtml($opts, Securimage::HTML_ICON_REFRESH) . '</td></tr>' .
                        '<tr><td class="title">' . Securimage::getCaptchaHtml($opts, Securimage::HTML_INPUT_LABEL) . '</td>' .
                        '<td class="input">' . Securimage::getCaptchaHtml($opts, Securimage::HTML_INPUT) . '</td></tr>' .
                        '</tbody>';

            $form['content'] = str_ireplace('</tbody>', $captcha, $form['content']);
        }

        return $form;
    }

    /**
     * Authenticate hook function.  Shows error if banned, or message on captcha failure.
     *
     * @param array $auth  Auth array
     * @return array
     */
    public function checkLogin($auth)
    {
        $banned       = $this->getBanInfo();
        $this->banned = ($banned !== false);

        if ($banned !== false) {
            $minutes       = ceil( ($banned['expires'] - time()) / 60);
            $auth['abort'] = true;
            $auth['error'] = $this->gettext('logsec_banned') . ' ' . sprintf($this->gettext('logsec_bantime'), $minutes);

            return $auth;
        }

        if (isset($this->captcha_passed) && !$this->captcha_passed) {
            $auth['abort'] = true;
            $auth['error'] = $this->gettext('incorrectcode');
            return $auth;
        }

        return $auth;
    }

    /**
     * Post login function.  Clears failed login count for user's IP
     *
     * @param array $params
     * @return array
     */
    public function loginAfter($params)
    {
        /*
         * Delete any failed logins from this ip after success
         */

        $this->rc->db->query(
            "DELETE FROM login_security_failures WHERE ip = ?",
            $this->ip
        );

        return $params;
    }

    /**
     * When application is ready and user is authenticated, handle OTP auth if necessary.
     * Access to the application is blocked until user passes OTP if enabled on their account.
     *
     * @param array $params task and action
     * @return array
     */
    public function ready($params)
    {
        if ($params['task'] == 'logout') {
            // logging out - do not require auth
            return $params;
        }

        if (isset($_SESSION['logsec_passed_auth']) && $_SESSION['logsec_passed_auth'] === true) {
            // already passed authentication
            return $params;
        }

        if ($this->cfg->logsec_otp_enabled == false) {
            // OTP functionality disabled via config
            $_SESSION['logsec_passed_auth'] = true;
            return $params;
        }

        $prefs = $this->rc->user->get_prefs();
        if (!isset($prefs['logsec_otp_enabled']) || $prefs['logsec_otp_enabled'] !== true) {
            // otp security not enabled
            $_SESSION['logsec_passed_auth'] = true;
            return $params;
        }

        if (empty($prefs['logsec_otp_secret'])) {
            // enabled but they don't have a secret
            $_SESSION['logsec_passed_auth'] = true;
            return $params;
        }

        $code = trim(rcube_utils::get_input_value('logsec_auth_code', RCUBE_INPUT_POST));

        if (!empty($code)) { // only validate if code is non-empty
            // generate totp object based on their secret
            $totp = new OTPHP\TOTP('', $prefs['logsec_otp_secret']);

            if ($totp->verify($code, null, 1)) {
                // code successfully verified
                $_SESSION['logsec_passed_auth'] = true;
                return $params;
            } elseif (isset($prefs['logsec_recovery_codes']) && is_array($prefs['logsec_recovery_codes'])) {
                // code was incorrect, but they have recover codes

                for ($i = 0; $i < self::NUM_RECOVERY_CODES; ++$i) {
                    if ($code == $prefs['logsec_recovery_codes'][$i]) {
                        // code matched one of the recovery codes
                        $_SESSION['logsec_passed_auth'] = true;
                        $prefs['logsec_recovery_codes'][$i] = ''; // clear code after use
                        $this->rc->user->save_prefs($prefs);
                        return $params;
                    }
                }
            }

            $this->incorrectCode = true;
        }

        $this->rc->output->add_handler('loginform', array(&$this, 'authenticate'));
        $this->rc->output->set_pagetitle('Authentication');
        $this->rc->output->send('login');
    }

    /**
     * Template handler for OTP auth form
     *
     * @return string HTML for template
     */
    public function authenticate()
    {
        ob_start();
        include __DIR__ . '/templates/authenticate.phtml';
        $html = ob_get_clean();

        return $html;
    }

    /**
     * Triggered if user authentication failed.  Increments failed login count, bans if over threshold.
     *
     * @param array $params
     */
    public function loginFailed($params)
    {
        /*
         * Increment failed login count for IP address w/ timestamp
         */
        if ($this->banned) {
            // already banned - don't increment failures or re-insert into ban table
            return ;
        }

        $this->rc->db->query(
            "INSERT INTO login_security_failures (ip, dt, mailbox) VALUES(?, NOW(), ?)",
            $this->ip, $params['user']
        );

        $failures = $this->getFailedLoginCount();

        if ($failures >= $this->cfg->logsec_ban_attempts) {
            $this->banIp();
        }
    }

    /**
     * Preferences section for login_security.
     *
     * @param array $params section and blocks
     * @return array
     */
    public function preferencesList($params)
    {
        if ($params['section'] != self::NAME) {
            return $params;
        }

        $prefs = $this->rc->user->get_prefs();

        // enabled checkbox
        $enabled = new html_checkbox(array(
            'name'  => 'logsec_otp_enabled',
            'id'    => 'logsec_otp_enabled',
            'value' => '1',
        ));

        // generate new otp secret
        $issuer = $this->rc->config->get('logsec_otp_issuer');
        $newsec = \Base32\Base32::encode($this->generateOtpSecret());
        $secret = new html_inputfield(array(
            'name'         => 'logsec_otp_secret',
            'id'           => 'logsec_otp_secret',
            'type'         => 'hidden',
            'autocomplete' => 'off',
            'value'        => $prefs['logsec_otp_secret'],
        ));

        // new secret provisioning uri
        $otp = new OTPHP\TOTP($this->rc->get_user_name(), $newsec);
        $otp->setIssuer($issuer);
        $otp->setIssuerIncludedAsParameter(true);
        $prov = $otp->getProvisioningUri(true);

        // existing secret re-provisioning uri
        $oldProv = null;
        if (isset($prefs['logsec_otp_secret']) && !empty($prefs['logsec_otp_secret'])) {
            $otp = new OTPHP\TOTP($this->rc->get_user_name(), $prefs['logsec_otp_secret']);
            $otp->setIssuer($issuer);
            $otp->setIssuerIncludedAsParameter(true);
            $oldProv = $otp->getProvisioningUri(true);
        }


        ob_start();
        include __DIR__ . '/templates/options.phtml';
        $gensecret = ob_get_clean();

        $params['blocks'][self::NAME]            = array();
        $params['blocks'][self::NAME]['name']    = $this->gettext('mainoptions');
        $params['blocks'][self::NAME]['options'] = array();
        $arr =& $params['blocks'][self::NAME]['options'];

        $arr['enabled'] = array(
            'title'   => html::label('logsec_otp_enabled', $this->gettext('enabled')),
            'content' => $enabled->show($prefs['logsec_otp_enabled'] === true),
        );

        $arr['secret'] = array(
            'title'   => $this->gettext('secret'),
            'content' => $secret->show() . $gensecret,
        );


        $recoveryContent  = $this->gettext('logsec_recovery_code_desc') . '<br>';
        $recoveryContent .= $this->gettext('logsec_recovery_code_desc2') . '<br>';
        $recoveryContent .= $this->gettext('logsec_recovery_code_desc3');
        $recoveryContent .= '<br><br>';

        for ($i = 0; $i < self::NUM_RECOVERY_CODES; ++$i) {
            $code = new html_inputfield(array(
                'name'         => 'logsec_recovery_codes[]',
                'type'         => 'text',
                'size'         => '15',
                'autocomplete' => 'off',
                'value'        => @$prefs['logsec_recovery_codes'][$i],
                'placeholder'  => @$placeholders[$i],
            ));
            $recoveryContent .= $code->show() . '&nbsp; &nbsp;';
        }

        $arr['recovery_codes'] = array(
            'title'   => $this->gettext('recoverycodes'),
            'content' => $recoveryContent,
        );

        return $params;
    }

    /**
     * Preferences section handler.  Adds login security to preferences sections list.
     *
     * @param array $params
     * @return array
     */
    public function preferencesSection($params)
    {
        if ($this->cfg->logsec_otp_enabled == false) {
            // otp disabled by config - don't add preferences section
            return $params;
        }

        $params['list'][self::NAME] = array(
            'id'      => self::NAME,
            'section' => rcube::Q($this->gettext('logsec_name')),
        );

        return $params;
    }

    /**
     * Save login security user preferences
     *
     * @param array $params
     * @return array
     */
    public function preferencesSave($params)
    {
        if ($params['section'] != self::NAME) {
            return $params;
        }

        $params['prefs']['logsec_otp_enabled']    = rcube_utils::get_input_value('logsec_otp_enabled', rcube_utils::INPUT_POST) ? true : false;
        $params['prefs']['logsec_otp_secret']     = rcube_utils::get_input_value('logsec_otp_secret', rcube_utils::INPUT_POST);
        $params['prefs']['logsec_recovery_codes'] = rcube_utils::get_input_value('logsec_recovery_codes', rcube_utils::INPUT_POST);

        return $params;
    }

    /*
     * Helper function to generate a new OTP secret key
     *
     * @return string  Secret key
     */
    protected function generateOtpSecret()
    {
        $len = 10;

        if (function_exists('random_bytes')) {
            return random_bytes($len);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            return openssl_random_pseudo_bytes($len);
        } else {
            // no secure random generator
            // not ideal but since otp codes are short lived, this doesn't
            // need to be crytographically secure
            $secret = '';

            for ($i = 0; $i < $len; ++$i) {
                $secret .= pack('c', mt_rand(0, 255));
                usleep(mt_rand(99, 172345));
            }

            return $secret;
        }
    }

    /*
     * Gets the current number of failed logins for an IP
     *
     * @return int The number of failed logins
     */
    protected function getFailedLoginCount()
    {
        $stmt = $this->rc->db->query(
            "SELECT COUNT(*) AS count FROM login_security_failures WHERE ip = ? AND NOW() - dt < ?",
            $this->ip,
            60 * $this->cfg->logsec_ban_threshold
        );

        $res = $this->rc->db->fetch_assoc($stmt);

        if (!$res) {
            return 0;
        } else {
            return $res['count'];
        }
    }

    /**
     * Add an IP to the ban table
     */
    protected function banIp()
    {
        $mins = $this->cfg->logsec_ban_time;

        $this->rc->db->query(
            "INSERT INTO login_security_bans (`ip`, `created`, `expires`) VALUES(?, NOW(), FROM_UNIXTIME(?))",
            $this->ip, time() + (60 * $mins)
        );
    }

    /**
     * Gets whether or not an IP is banned, and how many more minutes until the ban expires
     *
     * @return array  IP and minutes to expiration
     */
    protected function getBanInfo()
    {
        $stmt = $this->rc->db->query(
            "SELECT ip, UNIX_TIMESTAMP(expires) AS expires FROM login_security_bans WHERE `ip` = ?",
            $this->ip
        );
        $res  = $this->rc->db->fetch_assoc($stmt);

        return $res;
    }

    /**
     * Clean up old failed login entries
     */
    protected function gc()
    {
        $threshold = intval($this->cfg->logsec_ban_threshold) * 60;
        if ($threshold < 1) {
            $threshold = 900;
        }

        $this->rc->db->query("DELETE FROM login_security_failures WHERE UNIX_TIMESTAMP() - UNIX_TIMESTAMP(`dt`) > ?", $threshold);
        $this->rc->db->query("DELETE FROM login_security_bans WHERE NOW() >= `expires`");
    }
}
