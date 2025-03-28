<?php
namespace Auth\Services;

use Auth\Config\Redis;
use Auth\Entity\User;


class RedisService
{

    private $redis;

    public function __construct()
    {

        $this->redis = Redis::getClient();
    }



    public function getDataByToken(string $token): int
    {
        $storedUserId = $this->redis->get("token:$token");
        return (int) $storedUserId;
    }

    public function removeToken(string $token): void
    {
        $this->redis->del("token:$token");
    }

    public function setToken(string $token, int $time, User $user): void
    {
        $this->redis->setex("token:$token", $time, $user->id);
    }

    public function porcessAndDelteTokenByUserId(string $oldTokenKey, int $userId): void
    {
        $oldToken = $this->redis->get($oldTokenKey);

        if (!$oldToken) {
            // Caso o mapeamento reverso não exista, buscar manualmente entre as chaves token:*
            $tokenKeys = $this->redis->keys("token:*");
            foreach ($tokenKeys as $key) {
                if ($this->redis->get($key) == $userId) {
                    $oldToken = str_replace("token:", "", $key); // Extrai o token da chave
                    $this->redis->del($key); // Deleta o token antigo
                    break;
                }
            }
        } else {
            $this->redis->del("token:$oldToken"); // Deleta o token antigo do índice principal
        }
    }

    public function setDataOnCache(string $keyName, string $key, array $data)
    {
        $this->redis->setex("$keyName:$key", 3600, json_encode($data));
    }

    public function dropCachedData(string $keyName, string $key)
    {
        $this->redis->del("$keyName:$key");
    }

    public function getCachedData(string $keyName, string $key): mixed
    {
        return $this->redis->get("$keyName:$key");
    }
}