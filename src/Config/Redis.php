<?php
namespace Auth\Config;

use Predis\Client as RedisClient;

class Redis
{
    private static ?RedisClient $client = null;

    /**
     * Inicializa e retorna o cliente Redis
     */
    public static function getClient(): RedisClient
    {
        if (self::$client === null) {
            self::$client = new RedisClient([
                'scheme' => 'tcp',
                'host' => $_ENV['REDIS_HOST'] ?? '127.0.0.1',
                'port' => $_ENV['REDIS_PORT'] ?? 6379,
                'password' => $_ENV['REDIS_PASSWORD'] ?? null,
            ]);

            // Verifica a conexão
            try {
                self::$client->ping();
            } catch (\Exception $e) {
                throw new \Exception("Falha ao conectar ao Redis: " . $e->getMessage());
            }
        }

        return self::$client;
    }
}