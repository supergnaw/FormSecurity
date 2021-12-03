<?php
	declare( strict_types = 1 );
	
	namespace supergnaw;

	class FormSecurity {

		public static function start_session(): bool
		{
			if( PHP_SESSION_ACTIVE !== session_status()) {
				session_start();
				if( PHP_SESSION_ACTIVE !== session_status()) {
					return false;
				} else {
					return true;
				}
			} else {
				return true;
			}
		}

		// Generate a single-use token
		public static function token_generate( string $tokenName ): string
		{
			// start php session
			FormSecurity::start_session();

			// generate a unique hash and associate it to the given token name
			$token = hash( 'sha256', uniqid( microtime(), true ));
			$_SESSION['form_security']['tokens'][$tokenName] = $token;

			// return the token value for use, such as in a single-use form
			return $token;
		}

		// Verify a single-use token
		public static function token_verify( string $tokenName, bool $persistant = false ): bool
		{
			// start php session
			FormSecurity::start_session();

			// check if a session is started and a token is transmitted, if not return false
			if ( !isset ( $_SESSION['form_security']['tokens'][$tokenName] )) {
				return false;
			}

			// check if the form is sent with token in it
			if ( !isset ( $_POST[$tokenName] )) {
				return false;
			}

			// compare the tokens against each other if they are still the same
			if ( $_SESSION['form_security']['tokens'][$tokenName] !== $_POST[$tokenName] ) {
				return false;
			}

			// clear valid token data to prevent reuse
			if( true !== $persistant ) {
				unset( $_SESSION['form_security']['tokens'][$tokenName] );
				unset( $_POST[$tokenName] );
			}

			// return successful verification
			return true;
		}

		// Clear all existing single-use tokens
		public static function token_clear_all(): void
		{
			// start php session
			FormSecurity::start_session();

			// clear all existing tokens
			$_SESSION['form_security']['tokens'] = [];
		}

		// Limit array to whitelist only keys
		public static function apply_whitelist( array $whitelist, array $input ): array
		{
			$output = [];
			foreach( $input as $key => $val ) {
				if( in_array( $key, $whitelist )) {
					$output[$key] = $val;
				};
			}
		}

		// Filter an imput based on expected data type
		public static function filter_input( array $types, string $input = "post", bool $applyWhitelist = false ): array
		{
			// Prepare vars
			$input = strtolower( trim( $input ));
			$filtered = [];
			$inputs = [
				'get' => INPUT_GET,
				'post' => INPUT_POST,
				'cookie' => INPUT_COOKIE,
				'server' => INPUT_SERVER,
				'env' => INPUT_ENV
			];

			// Return empty resutls
			if( 'get' === $input && empty( $_GET )) return $filtered;
			if( 'post' === $input && empty( $_POST )) return $filtered;
			if( 'cookie' === $input && empty( $_COOKIE )) return $filtered;
			if( 'server' === $input && empty( $_SERVER )) return $filtered;
			if( 'env' === $input && empty( $_ENV )) return $filtered;


			// Verify input type
			if( !array_key_exists( $input, $inputs )) {
				return $filtered;
			} else {
				$input = $inputs[$input];
			}

			$saniTypes = [
				// Booleans
				'bool' => ['options' => 'supergnaw\FormSecurity::filter_boolean'],
				// Numbers
				'float' => ['options' => 'supergnaw\FormSecurity::filter_float'],
				'hexint' => ['options' => 'supergnaw\FormSecurity::filter_hexint'],
				'int' => ['options' => 'supergnaw\FormSecurity::filter_int'],
				'octint' => ['options' => 'supergnaw\FormSecurity::filter_octint'],
				// Networking
				'ipv4' => ['options' => 'supergnaw\FormSecurity::filter_ipv4'],
				'ipv6' => ['options' => 'supergnaw\FormSecurity::filter_ipv6'],
				'mac' => ['options' => 'supergnaw\FormSecurity::filter_mac'],
				// Timestamps
				'date' => ['options' => 'supergnaw\FormSecurity::filter_date'],
				'time' => ['options' => 'supergnaw\FormSecurity::filter_time'],
				'timestamp' => ['options' => 'supergnaw\FormSecurity::filter_timestamp'],
				// Strings
				'string' => ['options' => 'supergnaw\FormSecurity::filter_string'],
				'alnum' => ['options' => 'supergnaw\FormSecurity::filter_alnum'],
				'url' => ['options' => 'supergnaw\FormSecurity::filter_url'],
				'email' => ['options' => 'supergnaw\FormSecurity::filter_email'],
				'htmlenc' => ['options' => 'supergnaw\FormSecurity::filter_htmlenc'],
			];

			// Loop through each type-assigned variable
			foreach( $types as $var => $type ) {
				// Get filter type
				$options = ( array_key_exists( $type, $saniTypes )) ? $saniTypes[$type] : "none";

				if( 'none' !== $options ) {
					// Apply filter
					$filtered[$var] = filter_input( $input, $var, FILTER_CALLBACK, $options );
				} else {
					// Apply whitelist as applicable
					if( false === $applyWhitelist ) {
						$filtered[$var] = filter_input( $input, $var, FILTER_UNSAFE_RAW );
					}
				}
			}

			// Return filtered input
			return $filtered;
		}

		// Filter a float
		public static function filter_boolean( $b )
		{
			return filter_var( $b, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE );
		}

		// Filter a float
		public static function filter_float( $f )
		{
			$f = filter_var( $f, FILTER_VALIDATE_FLOAT, FILTER_FLAG_ALLOW_THOUSAND | FILTER_NULL_ON_FAILURE );
			if( !empty( $f )) {
				$f = filter_var( $f, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION | FILTER_FLAG_ALLOW_THOUSAND );
			}
			return $f;
		}

		// Filter an integer
		public static function filter_int( $i )
		{
			$i = filter_var( $i, FILTER_VALIDATE_FLOAT, FILTER_FLAG_ALLOW_THOUSAND | FILTER_NULL_ON_FAILURE );
			if( !empty( $i )) {
				$i = filter_var( $i, FILTER_SANITIZE_NUMBER_INT );
			}
			return $i;
		}

		// Filter an integer in hex format
		public static function filter_hexint( $h )
		{
			return filter_var( $h, FILTER_VALIDATE_INT, FILTER_FLAG_ALLOW_HEX | FILTER_NULL_ON_FAILURE );
		}

		// Filter an integer in octal format
		public static function filter_octint( $o )
		{
			return filter_var( $o, FILTER_VALIDATE_INT, FILTER_FLAG_ALLOW_OCTAL | FILTER_NULL_ON_FAILURE );
		}

		// Filter an IPv4 address
		public static function filter_ipv4( string $ip )
		{
			return filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_NULL_ON_FAILURE );
		}

		// Filter an IPv6 address
		public static function filter_ipv6( string $ip )
		{
			return filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_NULL_ON_FAILURE );
		}

		// Filter a MAC
		public static function filter_mac( string $m )
		{
			$options = [
				'options' => [
					'regexp' => "/^(([a-f0-9]{2}[:\-]){5}[a-f0-9]{2}|([a-f0-9]{4}\.?){2}[a-f0-9]{4}|[a-f0-9]{12})$/",
					'flags' => FILTER_NULL_ON_FAILURE
				]
			];
			return filter_var( trim( $m ), FILTER_VALIDATE_REGEXP, $options );
		}

		// Filter a URL
		public static function filter_url( string $u )
		{
			return filter_var( trim( $u ), FILTER_VALIDATE_URL, FILTER_NULL_ON_FAILURE );
		}

		// Filter an email
		public static function filter_email( string $e )
		{
			return filter_var( trim( $u ), FILTER_VALIDATE_EMAIL, FILTER_NULL_ON_FAILURE );
		}

		// Filter string with html encoding
		public static function filter_htmlenc( string $h )
		{
			return filter_var( trim( $h ), FILTER_SANITIZE_STRING, FILTER_FLAG_ENCODE_LOW | FILTER_FLAG_ENCODE_HIGH | FILTER_FLAG_ENCODE_AMP );
		}

		// Filter a date
		public static function filter_date( string $d, string $format = 'Y-m-d' )
		{
			return supergnaw\FormSecurity::filter_datetime( $d, $format );
		}

		// Filter a time
		public static function filter_time( string $d, string $format = "H:i:s" )
		{
			return supergnaw\FormSecurity::filter_datetime( $d, $format );
		}

		// Filter a timestamp
		public static function filter_timestamp( string $d, string $format = "Y-m-d H:i:s" )
		{
			return supergnaw\FormSecurity::filter_datetime( $d, $format );
		}

		// Filter a datetime
		public static function filter_datetime( string $d, string $format )
		{
			$d = DateTime::createFromFormat( $format, trim( $d ));
			return $d && $d->format( $format ) === $d;
		}

		// sanitize
		public static function stripcleantohtml( string $s ): string
		{
			// should not have <html> tags
			// Restores the added slashes (ie.: " I\'m John " for security in output, and escapes them in htmlentities(ie.:  &quot; etc.)
			// Also strips any <html> tags it may encouter
			// Use: Anything that shouldn't contain html (pretty much everything that is not a textarea)
			return htmlentities( trim( strip_tags( stripslashes( $s ))), ENT_NOQUOTES, "UTF-8" );
		}

		// clean any type of text that should have html tags in it
		public static function cleantohtml( string $s ): string
		{
			// could have <html> tags
			// Restores the added slashes (ie.: " I\'m John " for security in output, and escapes them in htmlentities(ie.:  &quot; etc.)
			// It preserves any <html> tags in that they are encoded aswell (like &lt;html&gt;)
			// As an extra security, if people would try to inject tags that would become tags after stripping away bad characters,
			// we do still strip tags but only after htmlentities, so any genuine code examples will stay
			// Use: For input fields that may contain html, like a textarea
			return strip_tags( htmlentities( trim( stripslashes( $s ))), ENT_NOQUOTES, "UTF-8" );
		}

		// clean to exclusively letters
		public static function clean_to_alpha( string $s ): string
		{
			$s = ( ctype_alpha( trim( $s ))) ? trim( $s ) : preg_replace( "/[^a-zA-Z]/", "", $s );
			return $s;
		}

		// clean to exclusively alphanumeric
		public static function clean_to_alnum( string $s ): string
		{
			$s = ( ctype_alnum( trim( $s ))) ? trim( $s ) : preg_replace( "/[^0-9a-zA-Z]/", "", $s );
			return $s;
		}
	}
