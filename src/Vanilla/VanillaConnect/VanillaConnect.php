<?php
/**
 * @author Alexandre (DaazKu) Chouinard <alexandre.c@vanillaforums.com>
 * @copyright 2009-2017 Vanilla Forums Inc.
 * @license http://www.opensource.org/licenses/gpl-2.0.php GNU GPL v2
 */

namespace Vanilla\VanillaConnect;
use Firebase\JWT\JWT;

/**
 * Class VanillaConnect
 */
class VanillaConnect {
    /**
     * Version. Uses semantic versioning.
     * @link http://semver.org/
     */
    const VERSION = '1.0.0';

    /**
     * Time in seconds before a token is considered expired.
     */
    const TIMEOUT = 1200; // (20s * 60s = 1200s = 20 minutes)

    /**
     * The hashing algorithm used to sign the JSON Web Token (JWT).
     */
    const HASHING_ALGORITHM = 'HS256';

    /**
     * Template containing the JWT required claim's fields for an authentication request.
     */
    const JWT_AUTH_CLAIM_TEMPLATE = [
        'iat' => null, // (Timestamp) Issued At => Time at witch the JWT was created.
        'exp' => null, // (Timestamp) Expires At => Time at witch the JWT will be expired. iat + self::TIMEOUT
        'nonce' => null, // (string) Authorized party => client_id
        'version' => self::VERSION, // (string) VanillaConnect version.
    ];

    /**
     * Template containing the JWT required header's fields for an authentication request.
     */
    const JWT_AUTH_HEADER_TEMPLATE = [
        'alg' => self::HASHING_ALGORITHM,
        'azp' => null, // Authorized party => $clientID
        'typ' => 'JWT', // Type of token.
    ];

    /**
     * Template containing the JWT required claim's fields for a response.
     */
    const JWT_RESPONSE_CLAIM_TEMPLATE = [
        'id' => null, // (string) Identifier of the resource (usually a user) we want to authenticate.
        'iat' => null, // (Timestamp) Issued At => Time at witch the JWT was created.
        'exp' => null, // (Timestamp) Expires At => Time at witch the JWT will be expired. iat + self::TIMEOUT
        'nonce' => null, // (string) Authorized party => client_id
        'version' => self::VERSION, // (string) VanillaConnect version.
    ];

    /**
     * Template containing the JWT required header's fields for a response.
     */
    const JWT_RESPONSE_HEADER_TEMPLATE = self::JWT_AUTH_HEADER_TEMPLATE;

    /**
     * @var String Client identifier.
     */
    protected $clientID;

    /**
     * List of errors that were encountered during the validation process.
     *
     * @var array
     */
    private $errors = [];

    /**
     * @var String Secret used to hash the JWT.
     */
    protected $secret;

    /**
     * VanillaConnect constructor.
     *
     * @param $clientID
     * @param $secret
     */
    public function __construct($clientID, $secret) {
        $this->clientID = $clientID;
        $this->secret = $secret;
    }

    /**
     * Return any errors that occurred after a call to validateAuthentication() or signResponse().
     *
     * @return array
     */
    public function getErrors() {
        return $this->errors;
    }

    /**
     * @param array $nonce
     * @return string JWT or false on failure.
     */
    public function createAuthenticationJWT($nonce) {
        $authHeader = array_merge(
            self::JWT_AUTH_HEADER_TEMPLATE,
            ['azp' => $this->clientID]
        );
        $authPayload = self::JWT_AUTH_CLAIM_TEMPLATE;
        $authPayload['iat'] = time();
        $authPayload['exp'] = time() + self::TIMEOUT;
        $authPayload['nonce'] = $nonce;

        JWT::encode($payload, $this->secret, self::HASHING_ALGORITHM, null, $authHeader);
    }

    /**
     * @param string $nonce
     * @param array $payload
     * @return string JWT or false on failure.
     */
    public function createResponseJWT($nonce, array $payload) {
        $responseHeader = array_merge(
            self::JWT_RESPONSE_HEADER_TEMPLATE,
            ['azp' => $this->clientID]
        );
        $authPayload = array_merge(JWT_RESPONSE_CLAIM_TEMPLATE, $payload);
        $authPayload['iat'] = time();
        $authPayload['exp'] = time() + self::TIMEOUT;
        $authPayload['nonce'] = $nonce;

        JWT::encode($authPayload, $this->secret, self::HASHING_ALGORITHM, null, $responseHeader);
    }

    /**
     * Validate the authentication JWT and fill $this->errors if there is any error.
     *
     * @param string $jwt JSON Web Token (JWT)
     * @return array|bool The decoded payload or false otherwise.
     */
    public function validateAuthentication($jwt) {
        $this->errors = [];

        try {
            $payload = JWT::decode($jwt, $this->secret, [self::HASHING_ALGORITHM]);
            $header = JWT::jsonDecode(JWT::urlsafeB64Decode(explode('.', $jwt[0])));
            $this->validateAuthenticationHeader($header);
            $this->validateAuthenticationClaim($payload);

            if (empty($this->errors)) {
                return $payload;
            }
        } catch(Exception $e) {
            $this->errors['auth_jtw_decode_exception'] = $e->getMessage();
        }

        return false;
    }


    /**
     * Validate the response JWT and fill $this->errors if there is any error.
     *
     * @param string $jwt JSON Web Token (JWT)
     * @return bool True if the validation was a success, false otherwise.
     */
    public function validateResponse($jwt) {
        $valid = false;
        $this->errors = [];

        try {
            $payload = JWT::decode($jwt, $this->secret, [self::HASHING_ALGORITHM]);
            $header = JWT::jsonDecode(JWT::urlsafeB64Decode(explode('.', $jwt[0])));
            $this->validateResponseHeader($header);
            $this->validateResponseClaim($payload);

            if (empty($this->errors)) {
                $valid = true;
            }
        } catch(Exception $e) {
            $this->errors['response_jwt_decode_exception'] = $e->getMessage();
        }

        return $valid;
    }

    /**
     * Validate the authentication header and fill $this->errors if there is any error.
     *
     * @param array $payload JWT header.
     */
    private function validateAuthenticationHeader(array $payload) {
        if (!$this->validateHeaderFields($payload, 'auth')) {
            return;
        }
    }

    /**
     * Validate the authentication claim and fill $this->errors if there is any error.
     *
     * @param array $payload JWT claim.
     */
    private function validateAuthenticationClaim(array $payload) {
        $missingKeys = array_diff_key(self::JWT_AUTH_CLAIM_TEMPLATE, $payload);
        if (count($missingKeys)) {
            $this->errors['auth_missing_claim_item'] = 'The JWT claim is missing the following item(s): '.implode(', ', $missingKeys);
            return;
        }

        if (preg_match('/^\d+\.\d+\.\d+$/', $payload['version']) !== 1) {
            $this->errors['auth_invalid_version'] = 'Invalid version.';
            return;
        }

        if (version_compare(explode('.', self::VERSION)[0], explode('.', $payload['version'])[0]) === 1) {
            $this->errors['auth_incompatible_version'] = 'The request was issued with version '.$payload['version'].
                ' but this library needs a client of at least version '.self::VERSION;
            return;
        }
    }

    /**
     * @param $payload
     * @param $type
     * @return bool
     */
    private function validateHeaderFields($payload, $type) {
        $missingKeys = array_diff_key(constant(VanillaConnectValidator::class.'::JWT_'.strtoupper($type).'_CLAIM_TEMPLATE'), $payload);
        if (count($missingKeys)) {
            $this->errors[$type.'_missing_claim_item'] = 'The JWT claim is missing the following item(s): '.implode(', ', $missingKeys);
            return false;
        }

        if ($payload['azp'] !== $this->clientID) {
            $this->errors[$type.'_client_id_mismatch'] = 'The JWT was issued using a different ClientID(azp) than what was expected.';
            return false;
        }

        return true;
    }

    /**
     * Validate the response claim and fill $this->errors if there is any error.
     *
     * @param array $payload JWT claim.
     */
    private function validateResponseClaim(array $payload) {
        $missingKeys = array_diff_key(self::JWT_RESPONSE_CLAIM_TEMPLATE, $payload);
        if (count($missingKeys)) {
            $this->errors['response_missing_claim_item'] = 'The JWT claim is missing the following item(s): '.implode(', ', $missingKeys);
            return;
        }


    }

    /**
     * Validate the response header and fill $this->errors if there is any error.
     *
     * @param array $payload JWT claim.
     */
    private function validateResponseHeader(array $payload) {
        if (!$this->validateHeaderFields($payload, 'response')) {
            return;
        }
    }
}
