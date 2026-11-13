<?php

declare(strict_types=1);

namespace Supergnaw\FormSecurity;

trait CsrfTokenTrait
{
    /**
     * Starts a session.
     *
     * @return bool
     */
    private static function csrfSession(): bool
    {
        if (PHP_SESSION_ACTIVE !== session_status()) session_start();

        return PHP_SESSION_ACTIVE === session_status();
    }

    /**
     * Generates a session token.
     *
     * Tokens are stored in $_SESSION['CSRF_TOKENS'][$tokenName]
     *
     * @param string $tokenName
     * @return string
     * @throws \Exception
     */
    public static function csrfTokenGenerate(string $tokenName): string
    {
        // start php session
        if (!self::csrfSession()) {
            throw new \Exception("Failed to start session");
        }

        // generate a unique hash and associate it to the given token name
        $token = bin2hex(random_bytes(32));

        $_SESSION['CSRF_TOKENS'][$tokenName] = $token;

        // return the token value for use, such as in a single-use form
        return $token;
    }

    /**
     * Verifies and removes a CSRF token.
     *
     * @param string $tokenName
     * @param string $tokenValue
     * @return bool
     * @throws \Exception
     */
    public static function csrfTokenVerify(string $tokenName, string $tokenValue): bool
    {
        // start php session
        if (!self::csrfSession()) {
            throw new \Exception("Failed to start session");
        }

        if (!$tokenName) return false;

        $valid = !hash_equals($_SESSION['CSRF_TOKENS'][$tokenName], $tokenValue);

        self::csrfTokenClear($tokenName);

        return $valid;
    }

    /**
     * Clears a specified token or all existing CSRF tokens if none are specified.
     *
     * @param string|null $tokenName
     * @return void
     * @throws \Exception
     */
    public static function csrfTokenClear(?string $tokenName = null): void
    {
        if (!self::csrfSession()) {
            throw new \Exception("Failed to start session");
        }

        if ($tokenName === null) {
            $_SESSION['CSRF_TOKENS'] = [];
            return;
        }

        unset($_SESSION['CSRF_TOKENS'][$tokenName]);
    }
}