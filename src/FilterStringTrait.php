<?php

declare(strict_types=1);

namespace Supergnaw\FormSecurity;

trait FilterStringTrait
{
    public static function filterString(string $s): string
    {
        return trim($s);
    }

    public static function filterAlnum(string $a): ?string
    {
        $options = [
            'options' => [
                'regexp' => "/^[A-Z0-9]*$/i",
                'flags' => FILTER_NULL_ON_FAILURE
            ]
        ];
        return filter_var(trim($a), FILTER_VALIDATE_REGEXP, $options);
    }

    /**
     * Clean a string to only letters
     *
     * @param string $s
     * @return string
     */
    public static function filterAlpha(string $s): string
    {
        return (ctype_alpha(trim($s))) ? trim($s) : preg_replace("/[^a-zA-Z]/", "", $s);
    }

    public static function filterHex(string $h): ?string
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
    public static function filterUrl(string $u): ?string
    {
        return filter_var(trim($u), FILTER_VALIDATE_URL, FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter an email
     *
     * @param string $e
     * @return mixed
     */
    public static function filterEmail(string $e): ?string
    {
        return filter_var(trim($e), FILTER_VALIDATE_EMAIL, FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter HTML encoded
     * @param string $h
     * @return mixed
     */
    public static function filterHtmlEnc(string $h): ?string
    {
        return filter_var(trim($h), FILTER_SANITIZE_STRING, FILTER_FLAG_ENCODE_LOW | FILTER_FLAG_ENCODE_HIGH | FILTER_FLAG_ENCODE_AMP);
    }
}