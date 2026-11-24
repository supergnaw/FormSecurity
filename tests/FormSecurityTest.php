<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Supergnaw\FormSecurity\FormSecurity;

// this makes sure tests don't silently fail
ini_set('zend.assertions', '1');
ini_set('assert.exception', '1');

final class FormSecurityTest
{
    public static function testFilterBoolean(): void
    {
        $tests = [
            "true" => true,
            "false" => false,
            1 => true,
            0 => false,
        ];

        foreach ($tests as $input => $expected) {
            $result = FormSecurity::filterBoolean($input);
            assert(
                assertion: $result == $expected,
                description: "Expected $expected, got $result (input: $input)"
            );
        }
    }
}