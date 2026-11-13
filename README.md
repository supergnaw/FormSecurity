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

This package was designed with flexibility in mind. As such, all functions are static, and you can use most internal 
methods to sanitize and filter as you wish. See the [API documentation](/docs/api-reference.md) for detailed usage for
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
FormSecurity provides a consistent, reusable interface for these common security-related tasks while remaining 
framework-agnostic and dependency free to make it easy to include in any project.

### Philosophy

FormSecurity focuses on:

- No framework dependencies
- Simple static methods
- Secure defaults
- Reusable components
- Incremental adoption

----
## Features

### [Global Input Sanitization](/docs/input-sanitization.md)

Sanitize and validate data from:

- `$_GET`
- `$_POST`
- `$_COOKIE`
- `$_SERVER`
- `$_ENV`

Supports built-in filters for:

- Booleans
- Integers and floats
- Email addresses
- URLs
- IPv4 / IPv6 addresses
- MAC addresses
- Dates and timestamps
- Alphanumeric strings

```php
$post = FormSecurity::sanitizePost(['username' => 'string', 'password' => 'string'])
```

---

### [CSRF Protection](/docs/csrf-protection.md)

Generate, validate, and manage CSRF tokens with minimal setup.

```php
$token = FormSecurity::csrfTokenGenerate('login_form');
```

### [File Upload Security](/docs/file-uploads.md)

Safely process uploaded files by:

- Verifying MIME types
- Verifying file extensions
- Moving files securely
- Normalizing complex multi-file uploads

```php
$file = FormSecurity::processFileUpload($_FILES['file_upload'], './upload/dir');
```

### [Array Schena Helpers](/docs/array-helpers.md)

Convenience methods for:

- Whitelisting keys
- Blacklisting keys
- Filtering data structures