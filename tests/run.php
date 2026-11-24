<?php

// To run tests via composer in the terminal:
// : composer dump-autoload
// : composer test

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

// Ensure assertions are active and throw AssertionError on failure
ini_set('zend.assertions', '1');
ini_set('assert.exception', '1');

$passed = 0;

$instance = new FormSecurityTest();
foreach (get_class_methods($instance) as $method) {
    if (str_starts_with($method, 'test')) {
        $instance::$method();
        $passed++;
        echo ".";
    }
}

echo PHP_EOL . "OK ({$passed} tests passed)" . PHP_EOL;
