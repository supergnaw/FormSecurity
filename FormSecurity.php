<?php
    class FormSecurity {
        public $hacklog = __DIR__ . '/../logs/hacklog.log';

        public function __construct()
        {
            if( PHP_SESSION_ACTIVE !== session_status()) {
                session_start();
            }
        }

        // form tokens
        public function token_gen( string $tokenName ): string
        {
            $token = hash( 'sha256', uniqid( microtime(), true ));
            $_SESSION['tokens'][$tokenName] = $token;
            return $token;
        }

        public function token_verify( string $tokenName, bool $persistant = false ): bool
        {
            // check if a session is started and a token is transmitted, if not return an error0
            if ( !isset ( $_SESSION['tokens'][$tokenName] )) {
                return false;
            }

            // check if the form is sent with token in it
            if ( !isset ( $_POST[$tokenName] )) {
                return false;
            }

            // compare the tokens against each other if they are still the same
			if ( $_SESSION['tokens'][$tokenName] !== $_POST[$tokenName] ) {
                return false;
            }

			// clear valid token data to prevent reuse
            if( true !== $persistant ) {
                unset ( $_SESSION['tokens'][$tokenName] );
                unset ( $_POST[$tokenName] );
            }

            // return successful verification
			return true;
        }

        public function token_reset(): void
        {
            $_SESSION['tokens'] = array();
        }

        // validate url
        public static function valid_url( string $url = null ): bool
        {
            if( empty( $_SERVER['HTTP_REFERER'] )) {
                return false;
            }

            $url = ( empty( $url )) ? $_SERVER['HTTP_REFERER'] : $url;
            if( !filter_var( $url, FILTER_VALIDATE_URL )) {
                return false;
            } else {
                return true;
            }
        }

        // verify whitelist
        public static function verify_whitelist( string $whitelist, array $post = null, bool $allowEmpty = true )
        {
            $post = ( empty( $post )) ? $_POST : $post;
            foreach( $post as $key => $value ) {
                if( !in_array( $key, $whitelist )) {
                    return false;
                }
                if( true !== $allowEmpty && empty( $value ) && 0 !== $value ) {
                    return false;
                }
            }
            return true;
        }

        // sanitize
        public static function stripcleantohtml ( string $s ): string
        {
            // should not have <html> tags
            // Restores the added slashes (ie.: " I\'m John " for security in output, and escapes them in htmlentities(ie.:  &quot; etc.)
            // Also strips any <html> tags it may encouter
            // Use: Anything that shouldn't contain html (pretty much everything that is not a textarea)
            return htmlentities( trim( strip_tags( stripslashes( $s ))), ENT_NOQUOTES, "UTF-8" );
        }

        // clean any type of text that should have html tags in it
        public static function cleantohtml ( string $s ): string
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
        public static function cleantoalpha( string $s ): string
        {
            $s = ( ctype_alpha( trim( $s ))) ? trim( $s ) : preg_replace( "/[^a-zA-Z]/", "", $s );
            return $s;
        }
        
        // clean to exclusively alphanumeric
        public static function cleantoalnum( string $s ): string
        {
            $s = ( ctype_alnum( trim( $s ))) ? trim( $s ) : preg_replace( "/[^0-9a-zA-Z]/", "", $s );
            return $s;
        }
        
        // clean to exclusively numbers
        public static function cleantodigit( string $s ): string
        {
            $s = ( ctype_digit( trim( $s ))) ? trim( $s ) : preg_replace( "/[^0-9]/", "", $s );
            return $s;
        }
        
        // clean to decimal numbers
        public static function cleantodecimal( string $s ): string
        {
            return preg_replace( "/[^0-9\.]/", "", $s );
        }
        
        // verify a valid date
        public static function valid_date( string $date, string $format = 'Y-m-d' ): string
        {
            $d = DateTime::createFromFormat( $format, $date );
            return $d && $d->format( $format ) === $date;
        }
        
        // log hacks/errors
        public function log_hack( string $where, string $die = null )
        {
            $ip = $_SERVER["REMOTE_ADDR"];      // Get the IP from superglobal
            $host = gethostbyaddr( $ip );       // Try to locate the host of the attack
            $datetime = date( "Y-m-d H:i:s" );  // Log datetime of the attack

            // create a logging message with php heredoc syntax
            $logging = "[{$datetime}] {$ip}@{$host}: {$where}\n";
/*            $logging = <<<LOG
            \n
            << Start of Message >>
            There was a hacking attempt on your form. \n
            Date of Attacck: {$datetime}
            IP-Adress: {$ip} \n
            Host of Attacker: {$host}
            Point of Attack: {$where}
            << End of Message >>
            LOG;/**/

            // log the attack
            if( $handle = fopen( $this->hacklog, 'a' )) {
                fputs( $handle, $logging ); // write the data to file
                fclose( $handle );
            }

            // eithe return data or kill the script
            if( empty( $die )) {
                return array( 'date' => $datetime, 'ip' => $ip, 'host' => $host, 'poa' => $where );
            } else {
                die( $die );
            }
        }
    }
