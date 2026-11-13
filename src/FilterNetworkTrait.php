<?php

declare(strict_types=1);

namespace Supergnaw\FormSecurity;

trait FilterNetworkTrait
{
    /**
     * Filter an IPv4 address
     *
     * @param string $ip
     * @return mixed
     */
    public static function filterIpv4(string $ip): ?string
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_NULL_ON_FAILURE);
    }

    /**
     * Filter an IPv6 address
     * @param string $ip
     * @return mixed
     */
    public static function filterIpv6(string $ip): ?string
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
    public static function filterMac(string $m): ?string
    {
        $options = [
            'options' => [
                'regexp' => "/^(([a-f0-9]{2}\.?){5}[a-f0-9]{2}|([a-f0-9]{4}\.?){2}[a-f0-9]{4}|[a-f0-9]{12})$/",
                'flags' => FILTER_NULL_ON_FAILURE
            ]
        ];
        return filter_var(trim($m), FILTER_VALIDATE_REGEXP, $options);
    }
}