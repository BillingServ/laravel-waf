<?php

namespace BillingServ\LaravelWaf\Tests\Unit;

use BillingServ\LaravelWaf\Support\AltchaVerifier;
use PHPUnit\Framework\TestCase;

final class AltchaVerifierTest extends TestCase
{
    public function test_current_altcha_solution_payload_is_verified(): void
    {
        if (!class_exists('AltchaOrg\\Altcha\\CreateChallengeOptions')) {
            self::markTestSkipped('The current ALTCHA API is not installed.');
        }

        $secret = 'test-v2-secret';
        $algorithm = new \AltchaOrg\Altcha\Algorithm\Pbkdf2();
        $altcha = new \AltchaOrg\Altcha\Altcha(hmacSignatureSecret: $secret);
        $challenge = $altcha->createChallenge(new \AltchaOrg\Altcha\CreateChallengeOptions(
            algorithm: $algorithm,
            cost: 1,
            counter: 0,
            keyPrefixLength: 1,
            expiresAt: time() + 60,
        ));
        $solution = $altcha->solveChallenge(new \AltchaOrg\Altcha\SolveChallengeOptions(
            challenge: $challenge,
            algorithm: $algorithm,
            timeout: 2,
        ));

        self::assertNotNull($solution);

        $payload = new \AltchaOrg\Altcha\Payload($challenge, $solution);

        self::assertTrue((new AltchaVerifier($secret))->verify($payload->toBase64()));
        self::assertFalse((new AltchaVerifier($secret))->verify('invalid-payload'));
    }

    public function test_server_signature_payload_is_verified(): void
    {
        $secret = 'test-server-signature-secret';
        $verificationData = http_build_query([
            'verified' => 'true',
            'expire' => time() + 60,
        ]);
        $hash = hash('sha256', $verificationData, true);
        $payload = base64_encode(json_encode([
            'algorithm' => 'SHA-256',
            'verificationData' => $verificationData,
            'signature' => bin2hex(hash_hmac('sha256', $hash, $secret, true)),
            'verified' => true,
        ], JSON_THROW_ON_ERROR));

        self::assertTrue((new AltchaVerifier($secret, 'server_signature'))->verify($payload));
    }
}
