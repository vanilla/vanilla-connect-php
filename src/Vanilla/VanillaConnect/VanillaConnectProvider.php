<?php
/**
 * @author Alexandre (DaazKu) Chouinard <alexandre.c@vanillaforums.com>
 * @copyright 2009-2017 Vanilla Forums Inc.
 * @license http://www.opensource.org/licenses/gpl-2.0.php GNU GPL v2
 */

namespace Vanilla\VanillaConnect;

/**
 * Class VanillaConnectProvider
 *
 * Provider friendly class that does everything you need in one call.
 */
class VanillaConnectProvider {

    private $vanillaConnect;

    /**
     * VanillaConnectProvider constructor.
     *
     * @param $clientID
     * @param $secret
     */
    public function __construct($clientID, $secret) {
        $this->vanillaConnect = new VanillaConnect($clientID, $secret);
    }

    /**
     * Create a response JWT from an authentication JWT and some resource data.
     *
     * @param $authJWT JWT sent during the authentication request.
     * @param $resourcePayload The data to put in the response JWT's claim. Usually
     * @return string JWT
     */
    public function authenticate($authJWT, $resourcePayload) {
        $authPayload = $this->vanillaConnect->validateAuthentication($authJWT);
        if (!$authPayload) {
            $responsePayload = ['errors' => $this->getErrors()];
        } else {
            $responsePayload = $resourcePayload;
        }

        return $this->vanillaConnect->createResponseJWT($authPayload['nonce'], $responsePayload);
    }
}
