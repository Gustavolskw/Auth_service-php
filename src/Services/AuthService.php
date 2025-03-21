<?php
namespace Auth\Services;

use Auth\Config\Database;
use Auth\DTO\UserDTO;
use Auth\Entity\User;
use Auth\Message\RabbitMQProducer;
use Respect\Validation\Validator as v;
use Firebase\JWT\JWT;

class AuthService
{
    private $rabbitMQProducer;

    public function __construct()
    {
        Database::bootEloquent();
        $this->rabbitMQProducer = new RabbitMQProducer();
    }

    public function register(string $name, string $email, string $password): array
    {
        // Sem validação aqui, movida para o AuthController
        if (User::where('email', $email)->exists()) {
            throw new \Exception('Email already exists');
        }

        $user = User::create([
            'name' => $name,
            'email' => $email,
            'password' => $password,
        ]);

        $payload = [
            'iss' => 'auth_service',
            'sub' => $user->id,
            'email' => $user->email,
            'iat' => time(),
            'exp' => time() + 3600,
        ];
        $token = JWT::encode($payload, $_ENV['JWT_SECRET'], 'HS256');

        $message = json_encode(['event' => 'user_registered', 'user_id' => $user->id]);
        $this->rabbitMQProducer->publish($message);

        return [
            'message' => 'User registered successfully',
            'user_id' => $user->id,
            'token' => $token
        ];
    }

    public function getUserByEmail(string $email): ?UserDTO
    {
        $user = User::where('email', $email)->first();
        if (!$user) {
            return null;
        }
        return $user;
    }

    public function getAllUsers(): array
    {
        return User::all()->toArray();
    }
}