FROM php:8.2-apache

# Install system dependencies including cURL development libraries
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install PHP cURL extension
RUN docker-php-ext-install curl

# Copy connector into Apache's document root
COPY . /var/www/html/

# Ensure correct working directory
WORKDIR /var/www/html

# Expose HTTP port
EXPOSE 80

# Launch Apache in the foreground
CMD ["apache2-foreground"]