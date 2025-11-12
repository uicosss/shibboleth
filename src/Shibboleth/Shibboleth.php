<?php

namespace Uicosss\Shibboleth;

use DirectoryIterator;
use stdClass;

class Shibboleth
{
    const ALLOWED_NETIDS_FILENAME = 'allowed.netids';

    /**
     * @var string|null
     */
    private ?string $authorizationFile = null;

    /**
     * @var bool
     */
    private bool $authenticated = false;

    /**
     * @var bool
     */
    private bool $authorized = false;

    /**
     * @var stdClass
     */
    private stdClass $attributes;

    /**
     * @var mixed|null
     */
    private ?string $authorizationContext = null;

    /**
     * @var mixed|null
     */
    private $appDocumentRoot = null;

    /**
     * @var mixed|null
     */
    private $appState = null;

    /**
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->setConfig($config);
        $this->setAttributeValues();

        // Attempt to read the file from the document root
        if (is_readable($this->appDocumentRoot . '/' . self::ALLOWED_NETIDS_FILENAME)) {
            $this->authorizationFile = $this->appDocumentRoot . '/' . self::ALLOWED_NETIDS_FILENAME;
        }

        if (!is_null($this->authorizationContext) && is_readable(dirname($this->authorizationContext) . '/' . self::ALLOWED_NETIDS_FILENAME)) {
            // If there is a "closer" authorization file, override and use that one instead
            $this->authorizationFile = dirname($this->authorizationContext) . '/' . self::ALLOWED_NETIDS_FILENAME;
        }

        $this->authenticated = $this->authenticate();
        $this->authorized = $this->authorize();
    }

    /**
     * @param array $config
     * @return void
     */
    private function setConfig(array $config = []): void
    {
        $this->authorizationContext = $config['authorizationContext'];
        $this->appDocumentRoot = $config['appDocumentRoot'];
        $this->appState = $config['appState'] ?? null;
    }

    /**
     * Returns a list of passed Shibboleth Attribute keys
     *
     * @return string[]
     */
    private function passedAttributes(): array
    {
        $potentialAttributes = [
            'uid',                  // oid:0.9.2342.19200300.100.1.1 - uid
            'title',                // oid:2.5.4.12 - title
            'primary-affiliation',  // oid:1.3.6.1.4.1.5923.1.1.1.5 - eduPersonPrimaryAffiliation
            'o',                    // oid:2.5.4.10 - organizationName
            'ou',                   // oid:2.5.4.11 - organizationalUnit
            'mail',                 // oid:0.9.2342.19200300.100.1.3 - mail
            'iTrustUIN',            // oid:1.3.6.1.4.1.11483.101.4 - iTrustUIN
            'iTrustSuppress',       // oid:1.3.6.1.4.1.11483.101.3 - iTrustSuppress
            'givenName',            // oid:2.5.4.42 - givenName
            'eppn',                 // oid:1.3.6.1.4.1.5923.1.1.1.6 - eppn
            'displayName',          // oid:2.16.840.1.113730.3.1.241  - displayName
            'unscoped-affiliation'  // oid:1.3.6.1.4.1.5923.1.1.1.1 - eduPersonAffiliation
        ];

        foreach ($potentialAttributes as $key => $attribute) {
            if (empty($_SERVER[$attribute])) {
                unset($potentialAttributes[$key]);
            }
        }

        return $potentialAttributes;
    }

    /**
     * Sets the attributes passed from Shibboleth into the class
     *
     * @return void
     */
    public function setAttributeValues()
    {
        $values = new stdClass();

        foreach ($this->passedAttributes() as $attribute) {
            if (!empty($_SERVER[$attribute])) {
                $values->{$attribute} = $_SERVER[$attribute];
            }
        }

        $this->attributes = $values;
    }

    /**
     * Returns all Shibboleth attributes available for the user
     *
     * @return stdClass
     */
    public function getAttributes(): stdClass
    {
        return $this->attributes;
    }

    /**
     * Attempts to authenticate the user
     *
     * @return bool
     */
    public function authenticate(): bool
    {
        if ($this->isLocalDev()) {
            return true;
        }

        // This works on Windows IIS 10 and Linux w/ Apache
        if (!empty($_SERVER['AUTH_TYPE']) && strtolower($_SERVER['AUTH_TYPE']) == 'shibboleth') {
            return true;
        }

        return false;
    }

    /**
     * Returns if the user is Authenticated
     *
     * @return bool
     */
    public function isAuthenticated(): bool
    {
        return $this->authenticated;
    }

    /**
     * Attempts to the Authorize the user in the context of where the Shibboleth class was
     * instantiated
     *
     * @return bool
     */
    public function authorize(): bool
    {
        if ($this->isLocalDev()) {
            return true;
        }

        if (empty($this->authorizationFile) || !is_readable($this->authorizationFile)) {
            // Authorization file cannot be read, therefore user cannot be authorized
            return false;
        }

        // Parse allowed.netids File
        $authorizationFileContents = file_get_contents($this->authorizationFile);

        // Determine which <allow *> are being used
        preg_match_all('/<allow (ip|NetIDs|groups)>/mi', $authorizationFileContents, $foundAllowArray);

        $structuredAuthorizationList = [
            'ip' => [],
            'netids' => [],
            'groups' => []
        ];

        $trackingIPs = false;
        $trackingNetIDs = false;
        $trackingGroups = false;

        // Sequentially process File
        foreach (preg_split("/((\r?\n)|(\r\n?))/", $authorizationFileContents) as $line) {
            if (empty($line)) {
                continue;
            }

            if (substr($line, 0, 1) == '#') {
                continue;
            }

            // By IP
            if (strtolower($line) == '<allow ip>') {
                $trackingIPs = true;
                continue;
            }

            if ($trackingIPs) {
                if (empty($line) or substr($line, 0, 1) == '<') {
                    $trackingIPs = false;
                } else {
                    $structuredAuthorizationList['ip'][] = $this->cleanAccessListLine($line);
                }
            }

            // By NetIDs
            if (strtolower($line) == '<allow netids>') {
                $trackingNetIDs = true;
                continue;
            }

            if ($trackingNetIDs) {
                if (empty($line) or substr($line, 0, 1) == '<') {
                    $trackingNetIDs = false;
                } else {
                    $structuredAuthorizationList['netids'][] = $this->cleanAccessListLine($line);
                }
            }

            // By groups
            if (strtolower($line) == '<allow groups>') {
                $trackingGroups = true;
                continue;
            }

            if ($trackingGroups) {
                if (empty($line) or substr($line, 0, 1) == '<') {
                    $trackingGroups = false;
                } else {
                    $structuredAuthorizationList['groups'][] = $this->cleanAccessListLine($line);
                }
            }

        }

        // Start with the more Permissive authorizations
        if (!empty($structuredAuthorizationList) and !empty($structuredAuthorizationList['groups'])) {
            foreach ($structuredAuthorizationList['groups'] as $group) {
                if ($group == 'all') {
                   return true;
                }

                if ($group == 'all@uic.edu') {
                    if (empty($this->attributes->mail)) {
                        $this->authorized =  false;
                    }

                    if (strpos($this->attributes->mail, '@uic.edu')) {
                       return true;
                    }
                }

                if ($group == 'all@uillinois.edu') {
                    if (empty($this->attributes->mail)) {
                        $this->authorized =  false;
                    }

                    if (strpos($this->attributes->mail, '@uillinois.edu')) {
                       return true;
                    }
                }

                if ($group == 'all@illinois.edu') {
                    if (empty($this->attributes->mail)) {
                        $this->authorized =  false;
                    }

                    if (strpos($this->attributes->mail, '@illinois.edu')) {
                       return true;
                    }
                }

                if ($group == 'all@uis.edu') {
                    if (empty($this->attributes->mail)) {
                        $this->authorized =  false;
                    }

                    if (strpos($this->attributes->mail, '@uis.edu')) {
                       return true;
                    }
                }
            }
        }

        if (!empty($structuredAuthorizationList) and !empty($structuredAuthorizationList['ip'])) {
            foreach ($structuredAuthorizationList['ip'] as $ip) {
                if (substr($ip, 0, 1) == '.') {
                    continue;
                }

                if (!empty($_SERVER['REMOTE_ADDR']) and substr($ip, 0, 1) != '*') {
                    if (strpos($_SERVER['REMOTE_ADDR'], str_replace('*', '', $ip)) === 0) {
                       return true;
                    }
                } elseif (!empty($_SERVER['REMOTE_ADDR']) and substr($ip, 0, 1) == '*') {
                    // todo - Match on domain name instead
                }
            }
        }

        if (!empty($structuredAuthorizationList) && !empty($structuredAuthorizationList['netids'])) {
            if (empty($this->attributes->uid)) {
                $this->authorized =  false;
                return false;
            }

            foreach ($structuredAuthorizationList['netids'] as $netid) {
                if (strtolower($netid) == strtolower($this->attributes->uid)) {
                   return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns whether the user is Authorized or not within the context of where the
     * Shibboleth class was instantiated
     *
     * @return bool
     */
    public function isAuthorized(): bool
    {
        return $this->authorized;
    }

    /**
     * Cleans up a given line getting rid of comments and other problematic character sequences
     *
     * @param $line
     * @return string
     */
    private function cleanAccessListLine($line): string
    {
        preg_match('/^[^#]*/', $line, $outputArray);

        if (!empty($outputArray[0])) {
            $line = $outputArray[0];
        }

        return trim($line);
    }

    /**
     * Renders an HTML template informing the user they are forbidden to see any content.
     *
     * @param string $assetPath
     * @return false|string
     */
    public function forbiddenMarkup(string $assetPath)
    {
        return file_get_contents($assetPath . '/forbidden.html');
    }

    /**
     * Renders an HTML template informing the user that they must authenticate before
     * seeing any content.
     *
     * @param string $assetPath
     * @param string|null $hostname
     * @param string|null $page
     * @return array|false|string|string[]
     */
    public function authenticationMarkup(string $assetPath, string $hostname = null, string $page = null)
    {
        $hostname = empty($hostname) ? $_SERVER['SERVER_NAME'] : $hostname;
        $page = empty($page) ? $_SERVER['PHP_SELF'] : $page;
        $urlEncodedTarget = urlencode('https://' . $hostname . $page);

        return str_replace('{{target}}', $urlEncodedTarget, file_get_contents($assetPath . '/authentication.html'));
    }

    /**
     * @return bool
     */
    private function isLocalDev(): bool
    {
        return in_array(strtolower($this->appState), ['dev', 'local']);
    }

    /**
     * Copies library assets into the full path provided.
     *
     * @param string $fullPath
     * @return void
     */
    public static function deployAssets(string $fullPath)
    {
        $dir = new DirectoryIterator(dirname(__DIR__) . '/assets');
        foreach ($dir as $file) {
            if (!$file->isDot()) {
                copy($file->getRealPath(), $fullPath . '/' . $file->getFilename());
            }
        }
    }
}