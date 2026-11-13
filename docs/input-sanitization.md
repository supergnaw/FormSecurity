# Global Input Sanitization (`$_GET`, `$_POST`, `$_COOKIE`, `$_SERVER`, `$_ENV`)

## Overview

`FormSecurity` uses an array filter schema to sanitize input globals where the filter key is the matching key in
the global array and the filter value is a string representing the type of value expected which can be any of
these:

- Boolean: `bool`
- Numeric: `float`, `int`, `hexint`, `octint`
- Network: `ipv4`, `ipv6`, `mac`
- Timestamps: `date`, `time`, `timestamp`
- Strings: `string`, `alnum`, `alpha`, `hex`, `url`, `email`, `htmlenc`

Each global has a dedicated method for sanitization so they do not need to be touched:

| Global     | Method                                        |
|:-----------|:----------------------------------------------|
| `$_GET`    | `FormSecurity::sanitizeGet(array $filter)`    |
| `$_POST`   | `FormSecurity::sanitizePost(array $filter)`   |
| `$_COOKIE` | `FormSecurity::sanitizeCookie(array $filter)` |
| `$_SERVER` | `FormSecurity::sanitizeServer(array $filter)` |
| `$_ENV`    | `FormSecurity::sanitizeEnv(array $filter)`    |

> **Note**
>
> FormSecurity uses a whitelist approach. Only fields defined in the filter schema will be returned in the resulting
> array. Inputs that fail the filter will be present with a `null` value.

## Examples

Valid values will be converted to the requested type whenever possible.

```php
//  $_GET = [
//      "input_one" => "1",
//      "input_two" => "2"
//  ]

$filter = [
    "input_one" => "int",
    "input_two" => "string",
];

$get = FormSecurity::sanitizeGet($filter);

echo $get["input_one"]; // 1
echo $get["input_two"]; // "2"
```

If a variable exists in the filter schema but fails validation,
it will be returned with a value of `null`.

Variables that are not defined in the filter schema will not be discarded
from the resulting array.

```php
//  $_POST[
//      "email" => "example@email.com",
//      "ip_addr" => "127.0.0.1",
//      "csrf_input" => "invalid"
//  ]

$filter = [
    "email" => "email",
    "ip_addr" => "ipv6",
];

$post = FormSecurity::sanitizePost($filter);

echo $post["email"]; // "example@email.com"
echo $post["ip_addr"]; // null
var_dump(isset($post["csrf_input"])); // bool(false)
```