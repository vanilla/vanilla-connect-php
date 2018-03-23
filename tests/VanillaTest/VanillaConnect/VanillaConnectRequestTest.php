<?php
/**
 * @author Alexandre (DaazKu) Chouinard <alexandre.c@vanillaforums.com>
 * @copyright 2009-2017 Vanilla Forums Inc.
 * @license http://www.opensource.org/licenses/gpl-2.0.php GNU GPL v2
 */

namespace VanillaTests\VanillaConnect;

use PHPUnit\Framework\TestCase;
use Vanilla\VanillaConnect\VanillaConnect;

class VanillaConnectRequestTest extends TestCase {

    /**
     * @var VanillaConnect
     */
    private static $vanillaConnect;

    /**
     * {@inheritdoc}
     */
    public static function setupBeforeClass() {
        self::$vanillaConnect = new VanillaConnect('TestClientID', 'TestSecret');
    }

    /**
     * Test a valid request.
     */
    public function testRequest() {
        $jti = uniqid();
        $state = ['a' => 'yay', 'b' => 'yup'];
        $jwt = self::$vanillaConnect->createRequestAuthJWT($jti, $state);

        $this->assertTrue(self::$vanillaConnect->validateRequest($jwt, $claim));

        $this->assertTrue(is_array($claim));
        $this->assertArrayHasKey('jti', $claim);
        $this->assertEquals($jti, $claim['jti']);

        $this->assertEquals($state, $claim['state']);

    }
}
