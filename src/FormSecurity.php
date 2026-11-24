<?php

declare(strict_types=1);

namespace Supergnaw\FormSecurity;

class FormSecurity
{
    use ArraySchemaTrait;
    use CsrfTokenTrait;
    use FileUploadTrait;
    use FilterNumberTrait;
    use FilterStringTrait;
    use FilterNetworkTrait;
    use FilterNumberTrait;
    use FilterBoolTrait;
    use FilterTimestampTrait;

    private const FILTERS = [
        // Booleans
        'bool' => "filterBoolean",
        // Numbers
        'float' => "filterFloat",
        'hexint' => "filterHexInt",
        'int' => "filterInt",
        'octint' => "filterOctint",
        // Networking
        'ipv4' => "filterIpv4",
        'ipv6' => "filterIpv6",
        'mac' => "filterMac",
        // Timestamps
        'date' => "filterDate",
        'time' => "filterTime",
        'timestamp' => "filterTimestamp",
        // Strings
        'string' => "filterString",
        'alnum' => "filterAlnum",
        'alpha' => "filterAlpha",
        'hex' => "filterHex",
        'url' => "filterUrl",
        'email' => "filterEmail",
        'htmlenc' => "filterHtmlEnc",
    ];

    /**
     * Sanitizes `$_GET` based on provided data type filters
     *
     * @param array $filters
     * @return array
     */
    public static function sanitizeGet(array $filters = []): array
    {
        if (empty($_GET)) return [];

        foreach($_GET as $key => $val) $_GET[$key] = urldecode($val);

        return self::sanitizeArray($_GET, $filters);
    }

    /**
     * Sanitizes `$_POST` based on provided data type filters
     *
     * @param array $filters
     * @return array
     */
    public static function sanitizePost(array $filters = []): array
    {
        if (empty($_POST)) return [];

        return self::sanitizeArray($_POST, $filters);
    }

    /**
     * Sanitizes `$_COOKIE` based on provided data type filters
     *
     * @param array $filters
     * @return array
     */
    public static function sanitizeCookie(array $filters = []): array
    {
        if (empty($_COOKIE)) return [];

        return self::sanitizeArray($_COOKIE, $filters);
    }

    /**
     * Sanitizes `$_SERVER` based on provided data type filters
     *
     * @param array $filters
     * @return array
     */
    public static function sanitizeServer(array $filters = []): array
    {
        if (empty($_SERVER)) return [];

        return self::sanitizeArray($_SERVER, $filters);
    }

    /**
     * Sanitizes `$_ENV` based on provided data type filters
     *
     * @param array $filters
     * @return array
     */
    public static function sanitizeEnv(array $filters = []): array
    {
        if (empty($_ENV)) return [];

        return self::sanitizeArray($_ENV, $filters);
    }

    public static function sanitizeArray(array $input, array $schema = []): array
    {
        $output = [];

        foreach ($input as $key => $val) {
            if (!array_key_exists($key, $schema)) continue;

            $filter = trim(strtolower($schema[$key]));

            if (!isset(self::FILTERS[$filter])) continue;

            $method = self::FILTERS[$filter];

            $output[$key] = self::$method($val);
        }

        return $output;
    }
}
