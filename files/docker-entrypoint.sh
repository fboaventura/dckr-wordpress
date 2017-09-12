#!/bin/bash
set -euo pipefail

export FQDN
export DOMAIN
export CAFILE
export CERTFILE
export KEYFILE
export FULLCHAIN

FQDN=${FQDN:-$(hostname --fqdn)}
DOMAIN=${DOMAIN:-$(hostname --domain)}

# usage: file_env VAR [DEFAULT]
#    ie: file_env 'XYZ_DB_PASSWORD' 'example'
# (will allow for "$XYZ_DB_PASSWORD_FILE" to fill in the value of
#  "$XYZ_DB_PASSWORD" from a file, especially for Docker's secrets feature)
file_env() {
	local var="$1"
	local fileVar="${var}_FILE"
	local def="${2:-}"
	if [ "${!var:-}" ] && [ "${!fileVar:-}" ]; then
		echo >&2 "error: both $var and $fileVar are set (but are exclusive)"
		exit 1
	fi
	local val="$def"
	if [ "${!var:-}" ]; then
		val="${!var}"
	elif [ "${!fileVar:-}" ]; then
		val="$(< "${!fileVar}")"
	fi
	export "$var"="$val"
	unset "$fileVar"
}

if [[ "$1" == apache2* ]] || [ "$1" == php-fpm ]; then
	if ! [ -e index.php -a -e wp-includes/version.php ]; then
		echo >&2 "WordPress not found in $PWD - copying now..."
		if [ "$(ls -A)" ]; then
			echo >&2 "WARNING: $PWD is not empty - press Ctrl+C now if this is an error!"
			( set -x; ls -A; sleep 10 )
		fi
		tar cf - --one-file-system -C /usr/src/wordpress . | tar xf -
		echo >&2 "Complete! WordPress has been successfully copied to $PWD"
		if [ ! -e .htaccess ]; then
			# NOTE: The "Indexes" option is disabled in the php:apache base image
			cat > .htaccess <<-'EOF'
				# BEGIN WordPress
				<IfModule mod_rewrite.c>
				RewriteEngine On
				RewriteBase /
				RewriteRule ^index\.php$ - [L]
				RewriteCond %{REQUEST_FILENAME} !-f
				RewriteCond %{REQUEST_FILENAME} !-d
				RewriteRule . /index.php [L]
				</IfModule>
				# END WordPress
			EOF
			chown www-data:www-data .htaccess
		fi
	fi

	# TODO handle WordPress upgrades magically in the same way, but only if wp-includes/version.php's $wp_version is less than /usr/src/wordpress/wp-includes/version.php's $wp_version

	# allow any of these "Authentication Unique Keys and Salts." to be specified via
	# environment variables with a "WORDPRESS_" prefix (ie, "WORDPRESS_AUTH_KEY")
	uniqueEnvs=(
		AUTH_KEY
		SECURE_AUTH_KEY
		LOGGED_IN_KEY
		NONCE_KEY
		AUTH_SALT
		SECURE_AUTH_SALT
		LOGGED_IN_SALT
		NONCE_SALT
	)
	envs=(
		WORDPRESS_DB_HOST
		WORDPRESS_DB_USER
		WORDPRESS_DB_PASSWORD
		WORDPRESS_DB_NAME
		"${uniqueEnvs[@]/#/WORDPRESS_}"
		WORDPRESS_TABLE_PREFIX
		WORDPRESS_DEBUG
	)
	haveConfig=
	for e in "${envs[@]}"; do
		file_env "$e"
		if [ -z "$haveConfig" ] && [ -n "${!e}" ]; then
			haveConfig=1
		fi
	done

	# linking backwards-compatibility
	if [ -n "${!MYSQL_ENV_MYSQL_*}" ]; then
		haveConfig=1
		# host defaults to "mysql" below if unspecified
		: "${WORDPRESS_DB_USER:=${MYSQL_ENV_MYSQL_USER:-root}}"
		if [ "$WORDPRESS_DB_USER" = 'root' ]; then
			: "${WORDPRESS_DB_PASSWORD:=${MYSQL_ENV_MYSQL_ROOT_PASSWORD:-}}"
		else
			: "${WORDPRESS_DB_PASSWORD:=${MYSQL_ENV_MYSQL_PASSWORD:-}}"
		fi
		: "${WORDPRESS_DB_NAME:=${MYSQL_ENV_MYSQL_DATABASE:-}}"
	fi

	# only touch "wp-config.php" if we have environment-supplied configuration values
	if [ "$haveConfig" ]; then
		: "${WORDPRESS_DB_HOST:=mysql}"
		: "${WORDPRESS_DB_USER:=root}"
		: "${WORDPRESS_DB_PASSWORD:=}"
		: "${WORDPRESS_DB_NAME:=wordpress}"

		# version 4.4.1 decided to switch to windows line endings, that breaks our seds and awks
		# https://github.com/docker-library/wordpress/issues/116
		# https://github.com/WordPress/WordPress/commit/1acedc542fba2482bab88ec70d4bea4b997a92e4
		sed -ri -e 's/\r$//' wp-config*

		if [ ! -e wp-config.php ]; then
			awk '/^\/\*.*stop editing.*\*\/$/ && c == 0 { c = 1; system("cat") } { print }' wp-config-sample.php > wp-config.php <<'EOPHP'
// If we're behind a proxy server and using HTTPS, we need to alert Wordpress of that fact
// see also http://codex.wordpress.org/Administration_Over_SSL#Using_a_Reverse_Proxy
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
	$_SERVER['HTTPS'] = 'on';
}

EOPHP
			chown www-data:www-data wp-config.php
		fi

		# see http://stackoverflow.com/a/2705678/433558
		sed_escape_lhs() {
			echo "$@" | sed -e 's/[]\/$*.^|[]/\\&/g'
		}
		sed_escape_rhs() {
			echo "$@" | sed -e 's/[\/&]/\\&/g'
		}
		php_escape() {
			php -r 'var_export(('$2') $argv[1]);' -- "$1"
		}
		set_config() {
			key="$1"
			value="$2"
			var_type="${3:-string}"
			start="(['\"])$(sed_escape_lhs "$key")\2\s*,"
			end="\);"
			if [ "${key:0:1}" = '$' ]; then
				start="^(\s*)$(sed_escape_lhs "$key")\s*="
				end=";"
			fi
			sed -ri -e "s/($start\s*).*($end)$/\1$(sed_escape_rhs "$(php_escape "$value" "$var_type")")\3/" wp-config.php
		}

		set_config 'DB_HOST' "$WORDPRESS_DB_HOST"
		set_config 'DB_USER' "$WORDPRESS_DB_USER"
		set_config 'DB_PASSWORD' "$WORDPRESS_DB_PASSWORD"
		set_config 'DB_NAME' "$WORDPRESS_DB_NAME"

		for unique in "${uniqueEnvs[@]}"; do
			uniqVar="WORDPRESS_$unique"
			if [ -n "${!uniqVar}" ]; then
				set_config "$unique" "${!uniqVar}"
			else
				# if not specified, let's generate a random value
				currentVal="$(sed -rn -e "s/define\((([\'\"])$unique\2\s*,\s*)(['\"])(.*)\3\);/\4/p" wp-config.php)"
				if [ "$currentVal" = 'put your unique phrase here' ]; then
					set_config "$unique" "$(head -c1m /dev/urandom | sha1sum | cut -d' ' -f1)"
				fi
			fi
		done

		if [ "$WORDPRESS_TABLE_PREFIX" ]; then
			set_config '$table_prefix' "$WORDPRESS_TABLE_PREFIX"
		fi

		if [ "$WORDPRESS_DEBUG" ]; then
			set_config 'WP_DEBUG' 1 boolean
		fi

		TERM=dumb php -- <<'EOPHP'
<?php
// database might not exist, so let's try creating it (just to be safe)

$stderr = fopen('php://stderr', 'w');

// https://codex.wordpress.org/Editing_wp-config.php#MySQL_Alternate_Port
//   "hostname:port"
// https://codex.wordpress.org/Editing_wp-config.php#MySQL_Sockets_or_Pipes
//   "hostname:unix-socket-path"
list($host, $socket) = explode(':', getenv('WORDPRESS_DB_HOST'), 2);
$port = 0;
if (is_numeric($socket)) {
	$port = (int) $socket;
	$socket = null;
}
$user = getenv('WORDPRESS_DB_USER');
$pass = getenv('WORDPRESS_DB_PASSWORD');
$dbName = getenv('WORDPRESS_DB_NAME');

$maxTries = 10;
do {
	$mysql = new mysqli($host, $user, $pass, '', $port, $socket);
	if ($mysql->connect_error) {
		fwrite($stderr, "\n" . 'MySQL Connection Error: (' . $mysql->connect_errno . ') ' . $mysql->connect_error . "\n");
		--$maxTries;
		if ($maxTries <= 0) {
			exit(1);
		}
		sleep(3);
	}
} while ($mysql->connect_error);

if (!$mysql->query('CREATE DATABASE IF NOT EXISTS `' . $mysql->real_escape_string($dbName) . '`')) {
	fwrite($stderr, "\n" . 'MySQL "CREATE DATABASE" Error: ' . $mysql->error . "\n");
	$mysql->close();
	exit(1);
}

$mysql->close();
EOPHP
	fi

	# now that we're definitely done writing configuration, let's clear out the relevant envrionment variables (so that stray "phpinfo()" calls don't leak secrets from our code)
	for e in "${envs[@]}"; do
		unset "$e"
	done
fi

# SSL CERTIFICATES
# ---------------------------------------------------------------------------------------------

LETS_ENCRYPT_LIVE_PATH=/etc/letsencrypt/live/"$FQDN"

if [ -d "$LETS_ENCRYPT_LIVE_PATH" ]; then

  echo "[INFO] Let's encrypt live directory found"
  echo "[INFO] Using $LETS_ENCRYPT_LIVE_PATH folder"

  FULLCHAIN="$LETS_ENCRYPT_LIVE_PATH"/fullchain.pem
  CAFILE="$LETS_ENCRYPT_LIVE_PATH"/chain.pem
  CERTFILE="$LETS_ENCRYPT_LIVE_PATH"/cert.pem
  KEYFILE="$LETS_ENCRYPT_LIVE_PATH"/privkey.pem

  # When using https://github.com/jwilder/nginx-proxy there is only key.pem
  # and fullchain.pem so we look for key.pem and extract cert.pem and chain.pem
  if [ ! -e "$KEYFILE" ]; then
    KEYFILE="$LETS_ENCRYPT_LIVE_PATH"/key.pem
  fi

  if [ ! -e "$KEYFILE" ]; then
    echo "[ERROR] No keyfile found in $LETS_ENCRYPT_LIVE_PATH !"
    exit 1
  fi

  if [ ! -e "$CAFILE" ] || [ ! -e "$CERTFILE" ]; then
    if [ ! -e "$FULLCHAIN" ]; then
      echo "[ERROR] No fullchain found in $LETS_ENCRYPT_LIVE_PATH !"
      exit 1
    fi

    awk -v path="$LETS_ENCRYPT_LIVE_PATH" 'BEGIN {c=0;} /BEGIN CERT/{c++} { print > path"/cert" c ".pem"}' < "$FULLCHAIN"
    mv "$LETS_ENCRYPT_LIVE_PATH"/cert1.pem "$CERTFILE"
    mv "$LETS_ENCRYPT_LIVE_PATH"/cert2.pem "$CAFILE"
  fi

else

  echo "[INFO] No Let's encrypt live directory found"
  echo "[INFO] Using /var/mail/ssl/selfsigned/ folder"

  FULLCHAIN=/var/mail/ssl/selfsigned/cert.pem
  CAFILE=
  CERTFILE=/var/mail/ssl/selfsigned/cert.pem
  KEYFILE=/var/mail/ssl/selfsigned/privkey.pem

  if [ ! -e "$CERTFILE" ] || [ ! -e "$KEYFILE" ]; then
    echo "[INFO] No SSL certificates found, generating a new selfsigned certificate"
    mkdir -p /var/mail/ssl/selfsigned/
    openssl req -new -newkey rsa:4096 -days 3658 -sha256 -nodes -x509 \
      -subj "/C=FR/ST=France/L=Paris/O=Mailserver certificate/OU=Mail/CN=*.${DOMAIN}/emailAddress=postmaster@${DOMAIN}" \
      -keyout "$KEYFILE" \
      -out "$CERTFILE"
  fi
fi

# DIFFIE-HELLMAN PARAMETERS
# ---------------------------------------------------------------------------------------------

if [ ! -e /var/mail/ssl/dhparams/dh2048.pem ] || [ ! -e /var/mail/ssl/dhparams/dh512.pem ]; then
  echo "[INFO] Diffie-Hellman parameters not found, generating new DH params"
  mkdir -p /var/mail/ssl/dhparams/
  openssl dhparam -out /var/mail/ssl/dhparams/dh2048.pem 2048
  openssl dhparam -out /var/mail/ssl/dhparams/dh512.pem 512
fi

sed -i "s@/etc/ssl/certs/ssl-cert-snakeoil.pem@${FULLCHAIN}@g;s@/etc/ssl/private/ssl-cert-snakeoil.key@${KEYFILE}@g" /etc/apache2/sites-available/default-ssl.conf

exec "$@"
