<?php
/**
 * @author Alexandre (DaazKu) Chouinard <alexandre.c@vanillaforums.com>
 * @copyright 2009-2017 Vanilla Forums Inc.
 * @license http://www.opensource.org/licenses/gpl-2.0.php GNU GPL v2
 */

namespace VanillaTests\VanillaConnect;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Vanilla\VanillaConnect\VanillaConnect;
use Vanilla\VanillaConnect\VanillaConnectProvider;

class VanillaConnectProviderTest extends TestCase {

    /**
     * @var VanillaConnect
     */
    private static $vanillaConnect;

    /**
     * @var VanillaConnectProvider
     */
    private static $vanillaConnectProvider;

    /**
     * {@inheritdoc}
     */
    public static function setupBeforeClass() {
        self::$vanillaConnect = new VanillaConnect('TestClientID', 'TestSecret');
        self::$vanillaConnectProvider = new VanillaConnectProvider(
            self::$vanillaConnect->getClientID(),
            self::$vanillaConnect->getSecret()
        );
    }

    /**
     * Test an error response.
     */
    public function testErrorResponse() {
        $erroneousRequestJWT = JWT::encode(
            [
                'iat' => time(),
                'exp' => time() + VanillaConnect::TIMEOUT,
                'nonce' => uniqid(),
                // Missing version.
            ],
            self::$vanillaConnect->getSecret(),
            VanillaConnect::HASHING_ALGORITHM,
            null,
            ['azp' => self::$vanillaConnect->getClientID()]
        );

        // This response will contain errors from the authentication request.
        $responseJWT = self::$vanillaConnectProvider->authenticate($erroneousRequestJWT, ['id' => uniqid()]);

        $this->assertFalse(self::$vanillaConnect->validateResponse($responseJWT));

        $errors = self::$vanillaConnect->getErrors();
        $this->assertTrue(!empty($errors));
        $this->assertArrayHasKey('request_missing_claim_item', $errors);
    }
}
