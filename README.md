# FormSecurity

## Overview

FormSecurity is a lightweight PHP security toolkit focused on form handling, request validation, file uploads, 
and CSRF protection.

Features include:

- CSRF token generation and validation
- Input sanitization for $_GET, $_POST, $_COOKIE, $_SERVER, and $_ENV
- Individual value filtering and validation helpers
- Secure file upload processing
- Array whitelisting and blacklisting utilities

Originally created as a simple [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) helper in 2021,
FormSecurity has evolved into a collection of reusable security utilities used across multiple projects.

### Granular Usage

This package was designed with flexibility in mind. As such, all functions are static and you can also use most internal
methods to sanitize and filter as you wish. See the [API documentation](api-documentation.md) for detailed usage for
every method.

## Quick Start

Make sure to update your composer installation:

```shell
composer require supergnaw/form-security
```

Then include the `use` statement and filter to your heart's content:

```php
use Supergnaw\FormSecurity;

$filter = [
    'email' => 'email',
    'age'   => 'int',
];

$data = FormSecurity::sanitizePost($filter);

if (empty($data)) {
    die('Invalid input');
}
```

----

## Why FormSecurity?

PHP provides many built-in functions for filtering input, processing file uploads, and managing CSRF protection.
FormSecurity provides a consistent, reusable interface for these common security-related tasks while remaining framework 
agnostic and dependency free to make it easy to include in any project.

----

## Global Input Sanitization (`$_GET`, `$_POST`, `$_COOKIE`, `$_SERVER`, `$_ENV`)

### Overview

`FormSecurity` uses an array filter schema to sanitize input globals where the filter key is the matching key in the
global array and the filter value is a string representing the type of value expected which can be any of these:

- Boolean: `"bool"`
- Numeric: `"float"`, `"int"`, `"hexint"`, `"octint"`
- Network: `"ipv4"`, `"ipv6"`, `"mac"`
- Timestamps: `"date"`, `"time"`, `"timestamp"`
- Strings: `"string"`, `"alnum"`, `"alpha"`, `"hex"`, `"url"`, `"email"`, `"htmlenc"`

*Note: if there is not a valid schema value for the filter, the key => value pair will be filtered out.*

#### Examples

The sanitization process will do its best to convert values to their types:

```php
//  $_GET = [
//      "foo" => "1",
//      "bar" => "2"
//  ]

$filter = [
    "foo" => "int",
    "bar" => "string",
];

$get = FormSecurity::sanitizeGet($filter);

echo $get["foo"]; // 1
echo $get["bar"]; // "2"
```

Only variables defined in the filter schema will be included in the resulting array.

If a variable does not exist, fails validation, or uses an unknown filter type, it will not be included in the returned
array.

```php
//  $_POST[
//      "foo" => "example@email.com",
//      "bar" => "127.0.0.1",
//      "baz" => "invalid"
//  ]

$filter = [
    "foo" => "email",
    "bar" => "ipv6",
];

$post = FormSecurity::sanitizePost($filter);

echo $post["foo"]; // "example@email.com"
isset($post["bar"]); // false
isset($post["baz"]); // false
```

----

## CSRF Protection

### Overview

FormSecurity can generate CSRF tokens to be used to verify a form can only be submitted once. To use the token, simply
generate a token, add it to a hidden form input, then validate the submitted token against the one saved in the session
variable.

#### Generate the token

```php
$token = FormSecurity::csrfGenerate('token_name');
```

#### Store the generated token in a form hidden input

```html

<form>
    ...
    <input type="hidden" name="token_name" value="<?php echo $token; ?>">
</form>
```

#### Validate the submitted token

```php
if (FormSecurity::csrfVerify("token_name")) {
    echo "security token is valid!";
} else {
    echo "security token is invalid!";
}
```

#### Clearing All Tokens

If for whatever reason you need to clear any saved tokens, use `token_clear_all()`.

```php
FormSecurity::csrfClearAll();
```

----

## File Upload Security

### Overview

FormSecurity provides helper methods for:

- Normalizing complex $_FILES arrays
- Validating uploaded file types
- Safely moving uploaded files
- Processing uploaded files using a consistent workflow

When verifying the MIME type of a file against the extension, these are the following tested and working pairs:

| Extension |          MIME Type           |
|:---------:|:----------------------------:|
|    pdf    |       application/pdf        |
|    zip    | application/x-zip-compressed |
|   json    |       application/json       |
|   mpeg    |          audio/mpeg          |
|    ogg    |          audio/ogg           |
|    csv    |           text/csv           |
|    txt    |          text/plain          |
|   jpeg    |          image/jpeg          |
|    jpg    |          image/jpg           |
|    png    |          image/png           |
|    gz     |      application/x-gzip      |
|    gif    |          image/gif           |
|   webp    |          image/webp          |
|    mp4    |          video/mp4           |
|    ogg    |          video/ogg           |

### Examples

A method built to easily process and validate file uploads is `processFileUpload()` which verifies the MIME against the
extension, creates a secure upload name, and moves it to the specified location:

```php
$uploadDir = '\path\to\upload\dir';
$fileUpload = $_FILES['file_upload_field'];
$fullUploadPath = FormSecurity::processFileUpload($fileUpload, $uploadDir);
```

When using a multi-file upload, the resulting array in $_FILES is collated, but this can be normalied with
`normalizedFilesArray()`, which also conveninently includes any upload error messages:

```php
//  $_FILES = [
//      'multi-file-upload' => [
//          'name' => [
//              0 => 'file01.png',
//              1 => 'file02.png',
//              2 => 'file03.png',
//          ],
//          'full_path' => [
//              0 => 'file01.png',
//              1 => 'file02.png',
//              2 => 'file03.png',
//          ],
//          'type' => [
//              0 => 'image/png',
//              1 => 'image/png',
//              2 => 'image/png',
//          ],
//          'tmp_name' => [
//              0 => '\tmp\path\php6338.tmp',
//              1 => '\tmp\path\php6349.tmp',
//              2 => '\tmp\path\php634A.tmp',
//          ],
//          'error' => [
//              0 => 3,
//              1 => 0,
//              2 => 0,
//          ],
//          'size' => [
//              0 => 1223047,
//              1 => 816063,
//              2 => 1015831,
//          ]
//      ]
//  ];

$files = FormSecurity::normalizeFilesArray($_FILES);

echo $files;

//  $files = [
//      'multi-file-upload' => [
//          0 => [
//              'ext' => 'png',
//              'name' => 'file01.png',
//              'full_path' => 'file01.png',
//              'type' => 'image/png',
//              'tmp_name' => '\tmp\path\php6338.tmp',
//              'error_message' => 'The uploaded file was only partially uploaded.',
//              'error' => 3,
//              'size' => 1223047,
//          ],
//          1 => [
//              'ext' => 'png',
//              'name' => 'file02.png',
//              'full_path' => 'file02.png',
//              'type' => 'image/png',
//              'tmp_name' => '\tmp\path\php6349.tmp',
//              'error_message' => '',
//              'error' => 0,
//              'size' => 816063,
//          ],
//          2 => [
//              'ext' => 'png',
//              'name' => 'file03.png',
//              'full_path' => 'file03.png',
//              'type' => 'image/png',
//              'tmp_name' => '\tmp\path\php634A.tmp',
//              'error_message' => '',
//              'error' => 0,
//              'size' => 1015831,
//          ],
//      ]
//  ];
```

----

## Array Helper Methods

These are still a work in progress, but the following functions have been implemented:

- `applyWhitelist()`: Applies a whitelist against an array and removes any keys not present in the $input array.
- `applyBlacklist()`: Applies a blacklist against an array and removes any keys present in the $input array.
