<?php
declare(strict_types=1);

namespace Supergnaw\FormSecurity;

trait FilterBoolTrait
{
    // BOOLEANS

    /**
     * Filter a boolean
     *
     * @param mixed $b
     * @return mixed
     */
    public static function filterBoolean(mixed $b): ?bool
    {
        return filter_var($b, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    }
}