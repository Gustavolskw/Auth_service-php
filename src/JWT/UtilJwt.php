<?php
namespace Auth\JWT;


use Auth\Entity\User;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;


class UtilJwt
{
    public function buildPayload(User $user): ?array
    {
        $payload = [
            'iss' => 'auth_service',
            'sub' => $user->id,
            'email' => $user->email,
            'role' => $user->role,
            'iat' => time(),
            'exp' => time() + 3600,
        ];
        return $payload;
    }

    public function encodeJwt(array $payload): string
    {
        return JWT::encode($payload, $_ENV['JWT_SECRET'], 'HS256');
    }

    public function decodeJwt($token): stdClass
    {
        $key = new Key($_ENV['JWT_SECRET'], 'HS256');
        $decoded = JWT::decode($token, $key);

        return $decoded;
    }


}