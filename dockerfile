# Use PHP 8.4 image
FROM php:8.4-cli

# Install required extensions and tools
RUN apt-get update && apt-get install -y \
    git unzip libzip-dev inotify-tools libssl-dev libcurl4-openssl-dev \
    && docker-php-ext-install zip sockets pdo pdo_mysql \
    && pecl install openswoole \
    && docker-php-ext-enable openswoole
# Install Composer (latest version)
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /

# Copy composer files first (to install dependencies early)
COPY composer.json composer.lock ./

# Install PHP dependencies
RUN composer install --no-dev --prefer-dist --no-interaction

# Run composer dump-autoload to optimize the autoloader
RUN composer dump-autoload --optimize

# Copy the rest of the application code
COPY . .

# Expose the port used by OpenSwoole server
EXPOSE 9502

# Default command to start the PHP server
CMD ["php", "server.php"]
