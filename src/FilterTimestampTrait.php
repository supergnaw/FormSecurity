<?php

declare(strict_types=1);

namespace Supergnaw\FormSecurity;

trait FilterTimestampTrait
{
    /**
     * Filter date
     *
     * Note: the format is 'Y-m-d'
     *
     * @param string $d
     * @param string $format
     * @return mixed
     */
    public static function filterDate(string $d): ?string
    {
        return self::filterDatetime($d, "Y-m-d");
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
    public static function filterTime(string $d): ?string
    {
        if (self::filterDatetime($d, "H:i:s")) {
            return $d;
        }
        return self::filterDatetime($d, "H:i");
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
    public static function filterTimestamp(string $d, string $format = "Y-m-d H:i:s"): ?string
    {
        return self::filterDatetime($d, $format);
    }

    /**
     * Filter a datetime based on a given $format
     *
     * @param string $d
     * @param string $format
     * @return mixed
     */
    public static function filterDatetime(string $d, string $format): ?string
    {
        $dt = DateTime::createFromFormat($format, trim($d));
        if ($dt && $dt->format($format) === $d) {
            return $d;
        }
        return null;
    }
}