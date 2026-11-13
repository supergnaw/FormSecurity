<?php
declare(strict_types=1);

namespace Supergnaw\FormSecurity;

trait ArraySchemaTrait
{
    /**
     * Applies a whitelist against an array and removes any keys not
     * present in the $input array
     *
     * @param array $whitelist
     * @param array $input
     * @return array
     */
    public static function applyWhitelist(array $whitelist, array $input): array
    {
        return array_intersect_key(
            $input,
            array_flip($whitelist)
        );
    }

    /**
     * Applies a blacklist against an array and removes any keys present
     * in the $input array
     *
     * @param array $blacklist
     * @param array $input
     * @return array
     */
    public static function applyBlacklist(array $blacklist, array $input): array
    {
        return array_diff_key(
            $input,
            array_flip($blacklist)
        );
    }


    protected static function removeEmpty(array $input): void
    {

    }

    protected static function requireKeys(array $keys, array $input): void
    {

    }

    protected static function hasKeys(array $keys, array $input): void
    {

    }

    protected static function pluck(): void
    {
        // this is probably unecessary because I can just use $arr['key'] unless
        // I'm misunderstanding the purpose of this function
    }

    protected static function renameKeys(array $keyMap, array $input): void
    {

    }
}