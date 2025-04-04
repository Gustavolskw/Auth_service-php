<?php
namespace Auth\Config;

use Dotenv\Dotenv;
use Illuminate\Database\Capsule\Manager as Capsule;

class Database
{
    public static function bootEloquent(): void
    {
        $dotenv = Dotenv::createImmutable(__DIR__ . '/../../');
        $dotenv->load();

        echo "DRIVER" . $_ENV['DB_DRIVER'];

        $capsule = new Capsule;
        $capsule->addConnection([
            'driver' => "mysql",
            'host' => $_ENV['DB_HOST'],
            'port' => $_ENV['DB_PORT'],
            'database' => $_ENV['DB_NAME'],
            'username' => $_ENV['DB_USER'],
            'password' => $_ENV['DB_PASS'],
            'charset' => 'utf8',
            'collation' => 'utf8_unicode_ci',
            'prefix' => '',
        ]);

        $capsule->setAsGlobal();
        $capsule->bootEloquent();
    }
}