<?php
declare(strict_types=1);

namespace Supergnaw\FormSecurity;

trait FilterBoolTrait
{
    // BOOLEANS

    /**
     * Filter a boolean
     *
     * @param $b
     * @return mixed
     */
    public static function filterBoolean($b): ?bool
    {
        return filter_var($b, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    }
}