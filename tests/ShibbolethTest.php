<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Uicosss\Shibboleth\Shibboleth;

final class ShibbolethTest extends TestCase
{
    /**
     * @covers Uicosss\Shibboleth\Shibboleth
     * @return void
     */
    public function testNoServerVariablesIsUnauthenticated(): void
    {
        $_SERVER = null;
        $_ENV = null;
        $_ENV['APP_DOCUMENT_ROOT'] = __DIR__ . '/Fixtures';
        $Shibboleth = new Shibboleth();
        $this->assertFalse($Shibboleth->isAuthenticated());
    }

    /**
     * @covers Uicosss\Shibboleth\Shibboleth
     * @return void
     */
    public function testWithServerVariablesIsAuthenticated(): void
    {
        $_SERVER = null;
        $_SERVER["uid"] = 'testuid';
        $_SERVER["title"] = 'Test Employee';
        $_SERVER["sn"] = 'Last';
        $_SERVER["primary-affiliation"] = 'staff';
        $_SERVER["ou"] = 'Student Systems Services, Office of';
        $_SERVER["mail"] = 'testuid@uic.edu';
        $_SERVER["iTrustUIN"] = '999999999';
        $_SERVER["iTrustSuppress"] = false;
        $_SERVER["givenName"] = 'First';
        $_SERVER["eppn"] = 'testuid@uic.edu';
        $_SERVER["displayName"] = 'First Last';
        $_SERVER["affiliation"] = 'member@uic.edu;staff@uic.edu';
        $_SERVER["AUTH_TYPE"] = 'shibboleth';

        $_ENV = null;
        $_ENV['APP_DOCUMENT_ROOT'] = __DIR__ . '/Fixtures';

        $Shibboleth = new Shibboleth();
        $this->assertTrue($Shibboleth->isAuthenticated());
    }

    /**
     * @covers Uicosss\Shibboleth\Shibboleth
     * @return void
     */
    public function testAuthorizedNoAccessIsForbidden(): void
    {
        $_SERVER = null;
        $_SERVER["uid"] = 'testuid';
        $_SERVER["title"] = 'Test Employee';
        $_SERVER["sn"] = 'Last';
        $_SERVER["primary-affiliation"] = 'staff';
        $_SERVER["ou"] = 'Student Systems Services, Office of';
        $_SERVER["mail"] = 'testuid@uic.edu';
        $_SERVER["iTrustUIN"] = '999999999';
        $_SERVER["iTrustSuppress"] = false;
        $_SERVER["givenName"] = 'First';
        $_SERVER["eppn"] = 'testuid@uic.edu';
        $_SERVER["displayName"] = 'First Last';
        $_SERVER["affiliation"] = 'member@uic.edu;staff@uic.edu';
        $_SERVER["AUTH_TYPE"] = 'shibboleth';

        $_ENV = null;
        $_ENV['APP_DOCUMENT_ROOT'] = '/tmp';

        $Shibboleth = new Shibboleth();
        $this->assertFalse($Shibboleth->isAuthorized());
    }

    /**
     * @covers Uicosss\Shibboleth\Shibboleth
     * @return void
     */
    public function testAuthorizedWithAccessIsAllowed(): void
    {
        $_SERVER = null;
        $_SERVER["uid"] = 'testuid';
        $_SERVER["title"] = 'Test Employee';
        $_SERVER["sn"] = 'Last';
        $_SERVER["primary-affiliation"] = 'staff';
        $_SERVER["ou"] = 'Student Systems Services, Office of';
        $_SERVER["mail"] = 'testuid@uic.edu';
        $_SERVER["iTrustUIN"] = '999999999';
        $_SERVER["iTrustSuppress"] = false;
        $_SERVER["givenName"] = 'First';
        $_SERVER["eppn"] = 'testuid@uic.edu';
        $_SERVER["displayName"] = 'First Last';
        $_SERVER["affiliation"] = 'member@uic.edu;staff@uic.edu';
        $_SERVER["AUTH_TYPE"] = 'shibboleth';

        $_ENV = null;
        $_ENV['APP_DOCUMENT_ROOT'] = __DIR__ . '/Fixtures';

        $Shibboleth = new Shibboleth();
        $this->assertTrue($Shibboleth->isAuthorized());
    }

    /**
     * @covers Uicosss\Shibboleth\Shibboleth
     * @return void
     */
    public function testAuthorizedWithAccessIsNotAllowedFromUnauthorizedUser(): void
    {
        $_SERVER = null;
        $_SERVER["uid"] = 'unauthuid';
        $_SERVER["title"] = 'Test Employee';
        $_SERVER["sn"] = 'Last';
        $_SERVER["primary-affiliation"] = 'staff';
        $_SERVER["ou"] = 'Student Systems Services, Office of';
        $_SERVER["mail"] = 'unauthuid@uic.edu';
        $_SERVER["iTrustUIN"] = '999999999';
        $_SERVER["iTrustSuppress"] = false;
        $_SERVER["givenName"] = 'First';
        $_SERVER["eppn"] = 'unauthuid@uic.edu';
        $_SERVER["displayName"] = 'First Last';
        $_SERVER["affiliation"] = 'member@uic.edu;staff@uic.edu';
        $_SERVER["AUTH_TYPE"] = 'shibboleth';

        $_ENV = null;
        $_ENV['APP_DOCUMENT_ROOT'] = __DIR__ . '/Fixtures';

        $Shibboleth = new Shibboleth();
        $this->assertFalse($Shibboleth->isAuthorized());
    }
}