# ScoutSuite Dashboard Frontend

## Installation

### 1. Install PHP and Nginx
```bash
# Ubuntu/Debian - Method 1 (PPA)
sudo apt update
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:ondrej/php
sudo apt update
sudo apt install nginx php8.1-fpm php8.1-mysql

# Ubuntu/Debian - Method 2 (Direct Source)
wget -qO /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/php.list
sudo apt update
sudo apt install nginx php8.1-fpm php8.1-mysql

# RHEL/CentOS
sudo yum install nginx php-fpm php-mysqlnd
```

### 2. Setup Directory
```bash
sudo mkdir -p /var/www/ScoutSuiteParser/frontend/www
sudo cp www/dashboard.php /var/www/ScoutSuiteParser/frontend/www/
sudo chown -R www-data:www-data /var/www/ScoutSuiteParser/frontend/www
```

### 3. Configure Nginx
```bash
sudo cp nginx/scoutsuite.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/scoutsuite.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 4. Configure PHP-FPM
```bash
sudo systemctl enable php8.1-fpm
sudo systemctl start php8.1-fpm
```

### 5. Set Database Environment Variables
```bash
# Add to /etc/environment or nginx config
export DB_HOST=localhost
export DB_USER=scoutsuite_user
export DB_PASSWORD=your_password
export DB_NAME=scoutsuite_db
```

### 6. Access Dashboard
Open browser to: `http://your-server-ip`