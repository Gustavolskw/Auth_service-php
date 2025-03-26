<?php
namespace Auth\Services;

use Auth\Config\Database;
use Auth\Entity\User;
use Auth\Message\RabbitMQProducer;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class AuthService
{
    private $rabbitMQProducer;

    public function __construct()
    {
        Database::bootEloquent();
        $this->rabbitMQProducer = new RabbitMQProducer();
    }

    public function loginUser(string $email, string $password): array
    {
        try {
            $userOnBase = User::where('email', $email)->first();
            if (!$userOnBase) {
                return [
                    'message' => 'User or Password invalid!',
                    'status' => 401
                ];
            }
        } catch (\Exception $e) {
            return [
                'message' => $e->getMessage(),
                'status' => 422
            ];
        }
        try {
            if (!password_verify($password, $userOnBase->password)) {
                return [
                    'message' => 'User or Password invalid!',
                    'status' => 401
                ];
            }

            $payload = [
                'iss' => 'auth_service',
                'sub' => $userOnBase->id,
                'email' => $userOnBase->email,
                'iat' => time(),
                'exp' => time() + 3600,
            ];

            $token = JWT::encode($payload, $_ENV['JWT_SECRET'], 'HS256');
            return [
                'message' => 'Logged in successfully',
                'status' => 200,
                'token' => $token,
            ];
        } catch (\Exception $e) {
            return [
                'message' => $e->getMessage(),
                'status' => 422
            ];
        }
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

    public function getUserByEmail(string $email): ?array
    {
        $user = User::where('email', $email)->first();
        if (!$user) {
            return null;
        }
        return $user->toArray();
    }

    public function getAllUsers(): array
    {
        return User::all()->toArray();
    }

    public function updateUser(string $token, string $name, string $email, string $password): array
    {
        try {
            // Decode JWT
            $key = new Key($_ENV['JWT_SECRET'], 'HS256');
            $decoded = JWT::decode($token, $key);

            $userId = $decoded->sub;
            $userEmail = $decoded->email;

            // Check if the new email is already in use
            if (User::where('email', $email)->exists() && $email !== $userEmail) {
                return [
                    'message' => "Email já em uso!",
                    'status' => 422
                ];
            }
            $user = User::find($userId);
            $user->name = $name;
            $user->email = $email;
            $user->password = $password;
            $user->save();

            // Prepare JWT payload
            $payload = [
                'iss' => 'auth_service',
                'sub' => $user->id,
                'email' => $user->email,
                'iat' => time(),
                'exp' => time() + 3600,
            ];

            // Generate new JWT token
            $tokenNew = JWT::encode($payload, $_ENV['JWT_SECRET'], 'HS256');

            // Return response
            return [
                'message' => 'User updated successfully',
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                ],
                'token' => $tokenNew
            ];

        } catch (\Exception $e) {
            // Catch errors and return them
            return [
                'message' => $e->getMessage(),
                'status' => 422
            ];
        }
    }
}