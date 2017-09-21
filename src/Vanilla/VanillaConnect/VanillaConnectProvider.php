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

    /**
     * @var VanillaConnect
     */
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
     * Create a response JWT, from an authentication JWT and some resource data, to authenticate a resource.
     *
     * @param $authJWT JWT sent during the authentication request.
     * @param $claim The data to put as the claim in the the response JWT. Needs to contain id.
     * @return string JWT
     */
    public function authenticate($authJWT, $claim) {
        if ($this->vanillaConnect->validateRequest($authJWT, $authClaim)) {
            $nonce = $authClaim['nonce'];
        } else {
            $nonce = null;
            $claim = ['errors' => $this->vanillaConnect->getErrors()];
        }

        return $this->vanillaConnect->createResponseAuthJWT($nonce, $claim);
    }

    /**
     * Create a response JWT to authenticate a resource.
     *
     * @param $resourcePayload The data to put in the response JWT's claim. Usually
     * @return string JWT
     */
    public function sso($resourcePayload) {
        // Set the audience to sso.
        $resourcePayload['aud'] = 'sso';
        return $this->vanillaConnect->createResponseAuthJWT(uniqid('vcrn_'), $resourcePayload);
    }
}
