<?php

declare(strict_types=1);

namespace Supergnaw\FormSecurity;

use DateTime;

class FormSecurity
{
    public const SANITYPES = [
        // Booleans
        'bool' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_boolean'],
        // Numbers
        'float' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_float'],
        'hexint' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_hexint'],
        'int' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_int'],
        'octint' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_octint'],
        // Networking
        'ipv4' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_ipv4'],
        'ipv6' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_ipv6'],
        'mac' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_mac'],
        // Timestamps
        'date' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_date'],
        'time' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_time'],
        'timestamp' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_timestamp'],
        // Strings
        'string' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_string'],
        'alnum' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_alnum'],
        'hex' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_hex'],
        'url' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_url'],
        'email' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_email'],
        'htmlenc' => ['options' => 'Supergnaw\FormSecurity\FormSecurity::filter_htmlenc'],
    ];
    /**
     * Starts a session
     *
     * @return bool
     */
    public static function start_session(): bool
    {
        if (PHP_SESSION_ACTIVE !== session_status()) {
            session_start();
            if (PHP_SESSION_ACTIVE !== session_status()) {
                return false;
            } else {
                return true;
            }
        } else {
            return true;
        }
    }

    /**
     * Generates a session token
     *
     * Tokens are stored in $_SESSION['form_security']['tokens'][$tokenName]
     *
     * @param string $tokenName
     * @return string
     */
    public static function token_generate(string $tokenName): string
    {
        // start php session
        FormSecurity::start_session();

        // generate a unique hash and associate it to the given token name
        $token = hash('sha256', uniqid(microtime(), true));
        $_SESSION['form_security']['tokens'][$tokenName] = $token;

        // return the token value for use, such as in a single-use form
        return $token;
    }

    /**
     * Verifies and removes a session token
     *
     * A token will remain with $persistant = true
     *
     * @param string $tokenName
     * @param bool $persistant
     * @return bool
     */
    public static function token_verify(string $tokenName, bool $persistant = false): bool
    {
        // start php session
        FormSecurity::start_session();

        // check if a session is started and a token is transmitted, if not return false
        if (!isset ($_SESSION['form_security']['tokens'][$tokenName])) {
            return false;
        }

        // check if the form is sent with token in it
        if (!isset ($_POST[$tokenName])) {
            return false;
        }

        // compare the tokens against each other if they are still the same
        if ($_SESSION['form_security']['tokens'][$tokenName] !== $_POST[$tokenName]) {
            return false;
        }

        // clear valid token data to prevent reuse
        if (true !== $persistant) {
            unset($_SESSION['form_security']['tokens'][$tokenName]);
            unset($_POST[$tokenName]);
        }

        // return successful verification
        return true;
    }

    /**
     * Clears all existing session tokens
     *
     * @return void
     */
    public static function token_clear_all(): void
    {
        // start php session
        FormSecurity::start_session();

        // clear all existing tokens
        $_SESSION['form_security']['tokens'] = [];
    }

    /**
     * Applies a whitelist against an array and removes any keys not
     * present in the $input array
     *
     * @param array $whitelist
     * @param array $input
     * @return array
     */
    public static function apply_whitelist(array $whitelist, array $input): array
    {
        $output = [];
        foreach ($input as $key => $val) {
            if (in_array($key, $whitelist)) {
                $output[$key] = $val;
            }
        }

        return $output;
    }

    /**
     * Applies a blacklist against an array and removes any keys present
     * in the $input array
     *
     * @param array $blacklist
     * @param array $input
     * @return array
     */
    public static function apply_blacklist(array $blacklist, array $input): array
    {
        foreach ($input as $key => $val) {
            if (in_array($key, $blacklist)) {
                unset($input[$key]);
            }
        }
        return $input;
    }

    /**
     * Filter an input based on expected data types
     *
     * @param string $input
     *      must be: post, get, cookie, env, server
     * @param array $types
     *      can be: bool, float, hexint, int, octint, ipv4, ipv6, mac, date, time,
     *              timestamp, string, alnum, url, email, htmlenc
     * @return array
     */
    public static function filter_input(string $input, array $types = []): array
    {
        // Prepare vars
        $input = strtolower(trim($input));
        $filtered = [];
        $inputs = [
            'post' => INPUT_POST,
            'get' => INPUT_GET,
            'cookie' => INPUT_COOKIE,
            'env' => INPUT_ENV,
            'server' => INPUT_SERVER /*,
            'session' => INPUT_SESSION, (not implemented yet)
            'request' => INPUT_REQUEST (not implemented yet)*/
        ];

        // Return empty results
        if ('post' === $input && empty($_POST)) return $filtered;
        if ('get' === $input && empty($_GET)) return $filtered;
        if ('cookie' === $input && empty($_COOKIE)) return $filtered;
        if ('env' === $input && empty($_ENV)) return $filtered;
        if ('server' === $input && empty($_SERVER)) return $filtered;
        /* https://www.php.net/manual/en/filter.constants.php (not implemented yet)
        if ('session' === $input && empty($_SESSION)) return $filtered;
        if ('request' === $input && empty($_REQUEST)) return $filtered;*/

        // Verify input type
        if (!array_key_exists($input, $inputs)) return $filtered;
        $input = $inputs[$input];

        // Loop through type-assigned variables to find expected type
        foreach ($types as $var => $type) {
            // Find expected variable type based on $types
            $options = (array_key_exists($type, FormSecurity::SANITYPES)) ? FormSecurity::SANITYPES[$type] : "none";

            $filtered[$var] = ('none' !== $options)
                // Use class built-in filtering function
                ? filter_input($input, $var, FILTER_CALLBACK, $options)
                // No type defined, use raw filtering function
                : filter_input($input, $var, FILTER_UNSAFE_RAW);
        }

        // Return filtered input
        return $filtered;
    }

    /**
     * Filter a boolean
     *
     * @param $b
     * @return mixed
     */
    public static function filter_boolean($b): bool | null
    {
        return filter_var($b, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter a float
     *
     * @param $f
     * @return mixed
     */
    public static function filter_float($f): float | null
    {
        $f = filter_var($f, FILTER_VALIDATE_FLOAT, FILTER_FLAG_ALLOW_THOUSAND | FILTER_NULL_ON_FAILURE);
        if (!empty($f)) {
            $f = filter_var($f, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION | FILTER_FLAG_ALLOW_THOUSAND);
        }
        return $f;
    }

    /**
     * Filter an integer
     *
     * @param $i
     * @return mixed
     */
    public static function filter_int($i): int | null
    {
        $i = filter_var($i, FILTER_VALIDATE_FLOAT, FILTER_FLAG_ALLOW_THOUSAND | FILTER_NULL_ON_FAILURE);
        if (!empty($i)) {
            $i = filter_var($i, FILTER_SANITIZE_NUMBER_INT);
        }
        return intval($i);
    }

    /**
     * Filter a hexint
     *
     * @param $h
     * @return mixed
     */
    public static function filter_hexint($h): string | null
    {
        return filter_var($h, FILTER_VALIDATE_INT, FILTER_FLAG_ALLOW_HEX | FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter an octint
     *
     * @param $o
     * @return mixed
     */
    public static function filter_octint($o): string | null
    {
        return filter_var($o, FILTER_VALIDATE_INT, FILTER_FLAG_ALLOW_OCTAL | FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter an IPv4 address
     *
     * @param string $ip
     * @return mixed
     */
    public static function filter_ipv4(string $ip): string | null
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter an IPv6 address
     * @param string $ip
     * @return mixed
     */
    public static function filter_ipv6(string $ip): string | null
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter a MAC address
     *
     * Valid formats are:
     *      01-23-45-67-89-AB
     *      CDEF-0123-4567
     *      890ABCDEF123
     *
     * Note: delimiters are optional and can be any character
     *
     * @param string $m
     * @return mixed
     */
    public static function filter_mac(string $m): string | null
    {
        $options = [
            'options' => [
                'regexp' => "/^(([a-f0-9]{2}\.?){5}[a-f0-9]{2}|([a-f0-9]{4}\.?){2}[a-f0-9]{4}|[a-f0-9]{12})$/",
                'flags' => FILTER_NULL_ON_FAILURE
            ]
        ];
        return filter_var(trim($m), FILTER_VALIDATE_REGEXP, $options);
    }

    public static function filter_string(string $s): string
    {
        return trim($s);
    }

    public static function filter_alnum(string $a): string | null
    {
        $options = [
            'options' => [
                'regexp' => "/^[A-Z0-9]*$/i",
                'flags' => FILTER_NULL_ON_FAILURE
            ]
        ];
        return filter_var(trim($a), FILTER_VALIDATE_REGEXP, $options);
    }

    public static function filter_hex(string $h): string | null
    {
        $options = [
            'options' => [
                'regexp' => "/^[A-F0-9]*$/i",
                'flags' => FILTER_NULL_ON_FAILURE
            ]
        ];
        return filter_var(trim($h), FILTER_VALIDATE_REGEXP, $options);
    }

    /**
     * Filter a URL
     *
     * @param string $u
     * @return mixed
     */
    public static function filter_url(string $u)
    {
        return filter_var(trim($u), FILTER_VALIDATE_URL, FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter an email
     *
     * @param string $e
     * @return mixed
     */
    public static function filter_email(string $e)
    {
        return filter_var(trim($e), FILTER_VALIDATE_EMAIL, FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter THML encoded
     * @param string $h
     * @return mixed
     */
    public static function filter_htmlenc(string $h)
    {
        return filter_var(trim($h), FILTER_SANITIZE_STRING, FILTER_FLAG_ENCODE_LOW | FILTER_FLAG_ENCODE_HIGH | FILTER_FLAG_ENCODE_AMP);
    }

    /**
     * Filter date
     *
     * Note: the format is 'Y-m-d'
     *
     * @param string $d
     * @param string $format
     * @return mixed
     */
    public static function filter_date(string $d): string | bool
    {
        return FormSecurity::filter_datetime($d, "Y-m-d");
    }

    /**
     * Filter a time
     *
     * Note: the format is 'H:i:s' with 'H:i' as a fallback
     *
     * @param string $d
     * @param string $format
     * @return mixed
     */
    public static function filter_time(string $d)
    {
        if (FormSecurity::filter_datetime($d, "H:i:s")) {
            return $d;
        }
        return FormSecurity::filter_datetime($d, "H:i");
    }

    /**
     * Filter a timestamp
     *
     * Note: the format is 'Y-m-d H:i:s'
     *
     * @param string $d
     * @param string $format
     * @return mixed
     */
    public static function filter_timestamp(string $d, string $format = "Y-m-d H:i:s"): string | bool
    {
        return FormSecurity::filter_datetime($d, $format);
    }

    /**
     * Filter a datetime based on a given $format
     *
     * @param string $d
     * @param string $format
     * @return mixed
     */
    public static function filter_datetime(string $d, string $format): string | bool
    {
        $dt = DateTime::createFromFormat($format, trim($d));
        if ($dt && $dt->format($format) === $d) {
            return $d;
        }
        return false;
    }

    /**
     * Clean a string to only letters
     *
     * @param string $s
     * @return string
     */
    public static function clean_to_alpha(string $s): string
    {
        return (ctype_alpha(trim($s))) ? trim($s) : preg_replace("/[^a-zA-Z]/", "", $s);
    }

    /**
     * Clean a string to only alphanumeric characters
     *
     * @param string $s
     * @return string
     */
    public static function clean_to_alnum(string $s): string
    {
        return (ctype_alnum(trim($s))) ? trim($s) : preg_replace("/[^0-9a-zA-Z]/", "", $s);
    }
}
