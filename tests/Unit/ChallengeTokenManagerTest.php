<?php

namespace BillingServ\LaravelWaf\Tests\Unit;

use BillingServ\LaravelWaf\Support\ChallengeTokenManager;
use PHPUnit\Framework\TestCase;

final class ChallengeTokenManagerTest extends TestCase
{
    public function test_issue_request_never_returns_a_token_larger_than_the_reader_accepts(): void
    {
        $manager = new ChallengeTokenManager('test-challenge-secret');
        $returnTo = '/'.str_repeat('"', 2047);

        self::assertNull($manager->issueRequest('203.0.113.38', $returnTo, 600));
    }
}
