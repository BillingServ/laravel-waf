<?php

namespace BillingServ\LaravelWaf\Support;

use BillingServ\LaravelWaf\Contracts\ChallengeVerifier;
use AltchaOrg\Altcha\Altcha;
use Throwable;

final class AltchaVerifier implements ChallengeVerifier
{
    public function __construct(
        private readonly string $hmacKey,
        private readonly string $verification = 'solution',
        private readonly int $maxPayloadBytes = 65536,
    ) {
    }

    public function verify(mixed $payload): bool
    {
        if ($this->hmacKey === '' || (!is_string($payload) && !is_array($payload))) {
            return false;
        }

        try {
            $payloadBytes = is_string($payload)
                ? strlen($payload)
                : strlen(json_encode($payload, JSON_THROW_ON_ERROR));
            if ($payloadBytes > max(1024, min(1048576, $this->maxPayloadBytes))) {
                return false;
            }

            if ($this->verification === 'server_signature') {
                return $this->verifyServerSignature($payload);
            }

            return $this->verifySolution($payload);
        } catch (Throwable) {
            return false;
        }
    }

    private function verifySolution(string|array $payload): bool
    {
        $data = $this->decode($payload);

        if (is_array($data)
            && is_array($data['challenge'] ?? null)
            && is_array($data['solution'] ?? null)
            && class_exists('AltchaOrg\\Altcha\\VerifySolutionOptions')) {
            $algorithm = $this->v2Algorithm($data['challenge']['parameters']['algorithm'] ?? null);
            if ($algorithm === null) {
                return false;
            }

            $altcha = new Altcha(hmacSignatureSecret: $this->hmacKey);
            $options = new \AltchaOrg\Altcha\VerifySolutionOptions($payload, $algorithm);

            return $altcha->verifySolution($options)->verified;
        }

        $class = class_exists('AltchaOrg\\Altcha\\V1\\Altcha')
            ? 'AltchaOrg\\Altcha\\V1\\Altcha'
            : Altcha::class;
        $altcha = new $class($this->hmacKey);

        return $altcha->verifySolution($payload, true);
    }

    private function verifyServerSignature(string|array $payload): bool
    {
        if (class_exists('AltchaOrg\\Altcha\\ServerSignature')) {
            return \AltchaOrg\Altcha\ServerSignature::verifyServerSignature($payload, $this->hmacKey)->verified;
        }

        $class = class_exists('AltchaOrg\\Altcha\\V1\\Altcha')
            ? 'AltchaOrg\\Altcha\\V1\\Altcha'
            : Altcha::class;

        return (new $class($this->hmacKey))->verifyServerSignature($payload)->verified;
    }

    /** @return array<string, mixed>|null */
    private function decode(string|array $payload): ?array
    {
        if (is_array($payload)) {
            return $payload;
        }

        $decoded = base64_decode($payload, true);
        if (!is_string($decoded)) {
            return null;
        }

        $data = json_decode($decoded, true);

        return is_array($data) ? $data : null;
    }

    private function v2Algorithm(mixed $name): ?object
    {
        if (!is_string($name)) {
            return null;
        }

        if (str_starts_with($name, 'PBKDF2/')) {
            $hmacName = substr($name, 7);
            $hmac = \AltchaOrg\Altcha\HmacAlgorithm::tryFrom($hmacName);
            if ($hmac === null) {
                return null;
            }

            return new \AltchaOrg\Altcha\Algorithm\Pbkdf2($hmac);
        }

        return match ($name) {
            'ARGON2ID' => new \AltchaOrg\Altcha\Algorithm\Argon2id(),
            'SCRYPT' => new \AltchaOrg\Altcha\Algorithm\Scrypt(),
            default => null,
        };
    }
}
