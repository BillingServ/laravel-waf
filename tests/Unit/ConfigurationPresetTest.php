<?php

namespace BillingServ\LaravelWaf\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class ConfigurationPresetTest extends TestCase
{
    /** @var array<string, array{process: string|false, env: mixed, env_exists: bool, server: mixed, server_exists: bool}> */
    private array $originalEnvironment = [];

    public function test_standard_preset_keeps_the_existing_defaults(): void
    {
        $config = $this->configuration(['LARAVEL_WAF_PRESET' => 'standard']);

        self::assertSame('standard', $config['preset']);
        self::assertSame('reject', $config['ddos']['mode']);
        self::assertFalse($config['ddos']['adaptive']['enabled']);
        self::assertSame('challenge', $config['behavior']['action']);
        self::assertFalse($config['login']['auto_block']);
        self::assertFalse($config['challenge']['enabled']);
        self::assertSame('default', $config['challenge']['provider']);
        self::assertSame(600, $config['challenge']['cookie_ttl_seconds']);
        self::assertSame('auto', $config['challenge']['cookie_secure']);
        self::assertSame('onsubmit', $config['challenge']['altcha']['auto']);
        self::assertFalse($config['challenge']['altcha']['auto_submit']);
        self::assertNull($config['challenge']['altcha']['display']);
        self::assertFalse($config['agent']['auto_block_on_limit']);
        self::assertFalse($config['agent']['auto_block_on_finding']);
        self::assertSame('/run/laravel-waf/metrics.sock', $config['metrics']['ingest']['socket']);
    }

    public function test_balanced_preset_replaces_the_verbose_application_settings(): void
    {
        $config = $this->configuration(['LARAVEL_WAF_PRESET' => 'balanced']);

        self::assertSame('balanced', $config['preset']);
        self::assertSame('challenge', $config['ddos']['mode']);
        self::assertTrue($config['ddos']['adaptive']['enabled']);
        self::assertSame('reject', $config['rules']['mode']);
        self::assertSame('reject', $config['behavior']['action']);
        self::assertTrue($config['login']['auto_block']);
        self::assertTrue($config['challenge']['enabled']);
        self::assertSame('altcha', $config['challenge']['provider']);
        self::assertSame('Checking your browser', $config['challenge']['title']);
        self::assertSame('This usually takes only a few seconds.', $config['challenge']['message']);
        self::assertSame(3600, $config['challenge']['cookie_ttl_seconds']);
        self::assertTrue($config['challenge']['cookie_secure']);
        self::assertSame('onload', $config['challenge']['altcha']['auto']);
        self::assertTrue($config['challenge']['altcha']['auto_submit']);
        self::assertSame('invisible', $config['challenge']['altcha']['display']);
        self::assertTrue($config['agent']['auto_block_on_limit']);
        self::assertTrue($config['agent']['auto_block_on_finding']);

        self::assertFalse($config['agent']['enabled']);
        self::assertFalse($config['metrics']['enabled']);
        self::assertSame('/run/laravel-waf/metrics.sock', $config['metrics']['ingest']['socket']);
        self::assertFalse($config['testing']['enabled']);
    }

    public function test_granular_environment_values_override_the_preset(): void
    {
        $config = $this->configuration([
            'LARAVEL_WAF_PRESET' => 'balanced',
            'LARAVEL_WAF_DDOS_MODE' => 'reject',
            'LARAVEL_WAF_LOGIN_AUTO_BLOCK' => 'false',
            'LARAVEL_WAF_CHALLENGE_COOKIE_SECURE' => 'auto',
            'LARAVEL_WAF_AGENT_AUTO_BLOCK' => 'false',
            'LARAVEL_WAF_AGENT_AUTO_BLOCK_ON_FINDING' => 'false',
            'LARAVEL_WAF_METRICS_SOCKET' => '/run/custom/lwafd-metrics.sock',
        ]);

        self::assertSame('reject', $config['ddos']['mode']);
        self::assertFalse($config['login']['auto_block']);
        self::assertSame('auto', $config['challenge']['cookie_secure']);
        self::assertFalse($config['agent']['auto_block_on_limit']);
        self::assertFalse($config['agent']['auto_block_on_finding']);
        self::assertSame('/run/custom/lwafd-metrics.sock', $config['metrics']['ingest']['socket']);
    }

    public function test_one_secret_supplies_every_waf_secret_consumer(): void
    {
        $config = $this->configuration([
            'LARAVEL_WAF_SECRET' => 'shared-waf-secret-with-at-least-32-bytes',
        ]);

        self::assertSame('shared-waf-secret-with-at-least-32-bytes', $config['secret']);
        self::assertSame('shared-waf-secret-with-at-least-32-bytes', $config['challenge']['cookie_secret']);
        self::assertSame('shared-waf-secret-with-at-least-32-bytes', $config['challenge']['altcha']['hmac_key']);
        self::assertSame('shared-waf-secret-with-at-least-32-bytes', $config['agent']['secret']);
        self::assertSame('shared-waf-secret-with-at-least-32-bytes', $config['agent']['gate']['token']);
        self::assertSame('shared-waf-secret-with-at-least-32-bytes', $config['metrics']['ingest']['secret']);
    }

    public function test_specific_secrets_remain_backward_compatible_overrides(): void
    {
        $config = $this->configuration([
            'LARAVEL_WAF_SECRET' => 'shared-waf-secret-with-at-least-32-bytes',
            'LARAVEL_WAF_CHALLENGE_COOKIE_SECRET' => 'legacy-cookie-secret-with-at-least-32-bytes',
            'LARAVEL_WAF_ALTCHA_HMAC_KEY' => 'legacy-altcha-secret-with-at-least-32-bytes',
            'LARAVEL_WAF_AGENT_SECRET' => 'legacy-agent-secret-with-at-least-32-bytes',
            'LARAVEL_WAF_AGENT_GATE_TOKEN' => 'legacy-gate-secret-with-at-least-32-bytes',
        ]);

        self::assertSame('legacy-cookie-secret-with-at-least-32-bytes', $config['challenge']['cookie_secret']);
        self::assertSame('legacy-altcha-secret-with-at-least-32-bytes', $config['challenge']['altcha']['hmac_key']);
        self::assertSame('legacy-agent-secret-with-at-least-32-bytes', $config['agent']['secret']);
        self::assertSame('legacy-gate-secret-with-at-least-32-bytes', $config['agent']['gate']['token']);
    }

    public function test_invalid_shared_secret_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('LARAVEL_WAF_SECRET');

        $this->configuration(['LARAVEL_WAF_SECRET' => 'too-short']);
    }

    public function test_unknown_preset_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('LARAVEL_WAF_PRESET');

        $this->configuration(['LARAVEL_WAF_PRESET' => 'aggressive']);
    }

    protected function tearDown(): void
    {
        foreach ($this->originalEnvironment as $key => $original) {
            if ($original['process'] === false) {
                putenv($key);
            } else {
                putenv($key.'='.$original['process']);
            }

            if ($original['env_exists']) {
                $_ENV[$key] = $original['env'];
            } else {
                unset($_ENV[$key]);
            }

            if ($original['server_exists']) {
                $_SERVER[$key] = $original['server'];
            } else {
                unset($_SERVER[$key]);
            }
        }

        parent::tearDown();
    }

    /** @param array<string, string> $variables */
    private function configuration(array $variables): array
    {
        foreach ($this->presetEnvironmentKeys() as $key) {
            $this->setEnvironment($key, $variables[$key] ?? null);
        }

        /** @var array<string, mixed> $config */
        $config = require __DIR__.'/../../config/laravel-waf.php';

        return $config;
    }

    private function setEnvironment(string $key, ?string $value): void
    {
        if (!array_key_exists($key, $this->originalEnvironment)) {
            $this->originalEnvironment[$key] = [
                'process' => getenv($key),
                'env' => $_ENV[$key] ?? null,
                'env_exists' => array_key_exists($key, $_ENV),
                'server' => $_SERVER[$key] ?? null,
                'server_exists' => array_key_exists($key, $_SERVER),
            ];
        }

        if ($value === null) {
            putenv($key);
            unset($_ENV[$key], $_SERVER[$key]);

            return;
        }

        putenv($key.'='.$value);
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
    }

    /** @return list<string> */
    private function presetEnvironmentKeys(): array
    {
        return [
            'LARAVEL_WAF_PRESET',
            'LARAVEL_WAF_SECRET',
            'LARAVEL_WAF_DDOS_MODE',
            'LARAVEL_WAF_ADAPTIVE_ENABLED',
            'LARAVEL_WAF_BEHAVIOR_ACTION',
            'LARAVEL_WAF_LOGIN_AUTO_BLOCK',
            'LARAVEL_WAF_CHALLENGE_ENABLED',
            'LARAVEL_WAF_CHALLENGE_PROVIDER',
            'LARAVEL_WAF_CHALLENGE_TITLE',
            'LARAVEL_WAF_CHALLENGE_MESSAGE',
            'LARAVEL_WAF_CHALLENGE_COOKIE_TTL',
            'LARAVEL_WAF_CHALLENGE_COOKIE_SECURE',
            'LARAVEL_WAF_CHALLENGE_COOKIE_SECRET',
            'LARAVEL_WAF_ALTCHA_HMAC_KEY',
            'ALTCHA_HMAC_KEY',
            'LARAVEL_WAF_ALTCHA_AUTO',
            'LARAVEL_WAF_ALTCHA_AUTO_SUBMIT',
            'LARAVEL_WAF_ALTCHA_DISPLAY',
            'LARAVEL_WAF_AGENT_AUTO_BLOCK',
            'LARAVEL_WAF_AGENT_AUTO_BLOCK_ON_FINDING',
            'LARAVEL_WAF_AGENT_ENABLED',
            'LARAVEL_WAF_AGENT_SECRET',
            'LARAVEL_WAF_AGENT_GATE_TOKEN',
            'LARAVEL_WAF_METRICS_ENABLED',
            'LARAVEL_WAF_METRICS_SOCKET',
            'LARAVEL_WAF_TESTING_ENABLED',
        ];
    }
}
