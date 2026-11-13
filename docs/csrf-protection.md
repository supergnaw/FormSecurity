# CSRF Protection

## Overview

FormSecurity can generate CSRF tokens to be used to verify a form can only be submitted once. To use the token, simply
generate a token, add it to a hidden form input, then validate the submitted token against the one saved in the session
variable.

| Method                                                   | Purpose                                               |
|----------------------------------------------------------|-------------------------------------------------------|
| `csrfTokenGenerate(string $tokenName)`                   | Generates a CSRF token.                               |
| `csrfTokenVerify(string $tokenName, string $tokenValue)` | Verifies and removes a session token.                 |
| `csrfTokenClear(?string $tokenName)`                     | Clears a specified token or all existing CSRF tokens. |

### Example

#### Generate the token

Generate the token using the same name that the form input field will use. The generated token is stored in
`$_SESSION['CSRF_TOKENS']` under the specified token name. Multiple tokens may be stored simultaneously.

```php
$token = FormSecurity::csrfTokenGenerate('token_name');
```

> **Note**
>
> There is no limit to the number of CSRF tokens that may be stored in `$_SESSION`.

#### Add the token to a form

In your HTML form, add a hidden form input with the same name that used to generate the token and echo the token value
into the form value.

```html

<form>
    ...
    <input type="hidden" name="token_name" value="<?php echo $token; ?>">
    ...
</form>
```

#### Validate the submitted token

In the code that will handle processing the request, add the code that will verify the token.

```php
if (FormSecurity::csrfTokenVerify("token_name")) {
    echo "security token is valid!";
} else {
    echo "security token is invalid!";
}
```

> **Warning**
>
> CSRF tokens are removed after successful validation.

#### Clear tokens

Validating a token will automatically clear out that token from $_SESSION, however there may be instances
when they remain in the global variable. In this case, you can clear individual tokens or all of them at once.

```php
// remove a specific token
FormSecurity::csrfTokenClear("token_name");

// remove all tokens
FormSecurity::csrfTokenClear();
```