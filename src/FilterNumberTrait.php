<?php

declare(strict_types=1);

namespace Supergnaw\FormSecurity;

trait FilterNumberTrait
{
    /**
     * Filter a float
     *
     * @param $f
     * @return mixed
     */
    public static function filterFloat($f): ?float
    {
        $f = filter_var($f, FILTER_VALIDATE_FLOAT, FILTER_FLAG_ALLOW_THOUSAND | FILTER_NULL_ON_FAILURE);
        if (!empty($f)) {
            $f = filter_var($f, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION | FILTER_FLAG_ALLOW_THOUSAND);
        }
        return $f;
    }

    /**
     * Filter a hexint
     *
     * @param $h
     * @return mixed
     */
    public static function filterHexInt($h): ?string
    {
        return filter_var($h, FILTER_VALIDATE_INT, FILTER_FLAG_ALLOW_HEX | FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter an integer
     *
     * @param $i
     * @return mixed
     */
    public static function filterInt($i): ?int
    {
        $i = filter_var($i, FILTER_VALIDATE_FLOAT, FILTER_FLAG_ALLOW_THOUSAND | FILTER_NULL_ON_FAILURE);
        if (!empty($i)) {
            $i = filter_var($i, FILTER_SANITIZE_NUMBER_INT);
        }
        return intval($i);
    }

    /**
     * Filter an octint
     *
     * @param $o
     * @return mixed
     */
    public static function filterOctint($o): ?string
    {
        return filter_var($o, FILTER_VALIDATE_INT, FILTER_FLAG_ALLOW_OCTAL | FILTER_NULL_ON_FAILURE);
    }
}