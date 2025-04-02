<?php
namespace Auth\Services;

use Auth\Config\Database;
use Auth\DTO\UserDTO;
use Auth\Entity\User;
use Auth\JWT\UtilJwt;
use Auth\Message\DirectQueueProducer;
use Auth\Message\FanoutExchangeProducer;
use Auth\Services\RedisService;

class AuthService
{
    private $rabbitMQProducer;

    private $rabbitMQDirectQueue;

    private $rabbitMQFanOutExge;

    private $redisService;

    private $utilJwt;

    public function __construct()
    {
        Database::bootEloquent();

        $this->redisService = new RedisService();
        $this->utilJwt = new UtilJwt();
        $this->rabbitMQDirectQueue = new DirectQueueProducer();
        $this->rabbitMQFanOutExge = new FanoutExchangeProducer();
    }

    public function loginUser(string $email, string $password): array
    {

        $userOnBase = User::where('email', $email)->first();
        if (!$userOnBase) {
            return $this->generateResponse('User or Password invalid!', 401);
        }


        if (boolval($userOnBase->status) == false) {
            return $this->generateResponse("Usuario Invalido!", 422);
        }


        if (!password_verify($password, $userOnBase->password)) {
            return $this->generateResponse('User or Password invalid!', 401);
        }

        $oldTokenKey = "user:{$userOnBase->id}:token";

        $this->redisService->porcessAndDelteTokenByUserId($oldTokenKey, $userOnBase->id);

        $payload = $this->utilJwt->buildPayload($userOnBase);

        $token = $this->utilJwt->encodeJwt($payload);


        $this->redisService->setToken($token, 3600, $userOnBase);

        return $this->generateResponse('Logged in successfully', 200, null, $token);

    }

    public function register(string $name, string $email, string $password, int $role = User::ROLE_USER): array
    {
        if (User::where('email', $email)->exists()) {
            return $this->generateResponse('Email Invalido ou indisponivel!', 422);
        }
        if (!in_array($role, [User::ROLE_USER, User::ROLE_ADMIN])) {
            return $this->generateResponse('Role inválido', 422);
        }

        $user = User::create([
            'name' => $name,
            'email' => $email,
            'password' => $password,
            'role' => $role,
            'status' => true
        ]);

        $user->save();

        $payload = $this->utilJwt->buildPayload($user);
        $token = $this->utilJwt->encodeJwt($payload);

        $this->redisService->setToken($token, 3600, $user);



        $userResponse = UserDTO::fromArray($user->toArray())->toArray();

        $this->rabbitMQDirectQueue->publish($_ENV['RABBITMQ_QUEUE'], ['userId' => $user->id, 'email' => $user->email]);

        $this->cleanUserCache();

        return $this->generateResponse('User registered successfully', 201, $userResponse, $token);
    }

    public function getUserByEmail(string $email): array
    {
        $user = User::where('email', "LIKE", $email)->first();
        if ($user == null) {
            return $this->generateResponse('Usuario nao encontrado!', 404);
        }
        //return $user->toArray();
        return $this->generateResponse('Usuario encontrado!', 200, UserDTO::fromArray($user->toArray())->toArray());
    }

    public function getAllUsers(): array
    {

        $usersCached = $this->redisService->getCachedData("userCache", "users");
        if (!$usersCached) {
            $users = User::all()->toArray();
            if ($users == null) {
                $this->generateResponse("Sem usuarios nos registros!", 200);
            }
            $this->setUserCache($users);
            $userDTOs = array_map(fn($user) => UserDTO::fromArray($user), $users);

            return $this->generateResponse("Lista de Usuarios", 200, array_map(fn($dto) => $dto->toArray(), $userDTOs));
        }
        if ($usersCached == null) {
            $this->generateResponse("Sem usuarios nos registros!", 200);
        }

        $users = json_decode($usersCached, true);

        $userDTOs = array_map(fn($user) => UserDTO::fromArray($user), $users);

        return $this->generateResponse("Lista de Usuarios", 200, array_map(fn($dto) => $dto->toArray(), $userDTOs));
    }

    public function updateUser(string $token, int $id, ?string $name, ?string $email, ?string $password, ?int $role = User::ROLE_USER, bool $status): array
    {

        if (!in_array($role, [User::ROLE_USER, User::ROLE_ADMIN])) {
            return $this->generateResponse("Cargo invalido!", 422);
        }
        $decoded = $this->utilJwt->decodeJwt($token);

        $userId = $decoded->sub;
        $userEmail = $decoded->email;

        $storedUserId = $this->redisService->getDataByToken($token);
        if (!$storedUserId || $storedUserId != $userId) {
            return $this->generateResponse('Invalid or missing token', 401);
        }

        if ($email && User::where('email', $email)->exists() && $email !== $userEmail) {
            return $this->generateResponse("Email already in use", 422);
        }

        if ($decoded->role >= User::ROLE_ADMIN) {
            $user = User::where("id", "=", $id)->first();
        } elseif ($userId == $id) {
            $user = User::where("id", "=", $userId)->first();
        } else {
            return $this->generateResponse("Action not allowed", 403);
        }
        if ($status == null) {
            if (!$user || boolval($user->status) === false) {
                return $this->generateResponse("Usuario Inativado, reative-o para poder Atualizar!", 422);
            }
        }

        $user->name = $name ?? $user->name;
        $user->email = $email ?? $user->email;
        $user->password = $password ?? $user->password;
        if ($userId != $id) {
            $user->role = $role ?? $user->role;
        } else if ($userId == $id && $role >= User::ROLE_ADMIN) {
            $user->role = $role ?? $user->role;
        }
        $user->status = $status ?? $user->status;

        if (isset($status) && boolval($user->status)) {
            $this->rabbitMQFanOutExge->publish($_ENV['RABBITMQ_FAN_OUT_EXCHANGE_REACT'], ['userId' => $user->id]);
        }

        $user->save();

        $this->cleanUserCache();
        if ($userId == $id) {
            $this->redisService->removeToken($token);

            $payload = $this->utilJwt->buildPayload($user);

            $tokenNew = $this->utilJwt->encodeJwt($payload);

            $this->redisService->setToken($token, 3600, $user);

            return $this->generateResponse('User updated successfully', 200, UserDTO::fromArray($user->toArray())->toArray(), $tokenNew);
        }
        return $this->generateResponse('User updated successfully', 200, UserDTO::fromArray($user->toArray())->toArray());

    }


    public function removeUser(int $id, string $token)
    {

        $decoded = $this->utilJwt->decodeJwt($token);
        $decodedId = $decoded->sub;
        $decodedRole = $decoded->role;

        echo "$decodedId e o id vindo do request $id \n";

        if ($decodedId == $id) {
            $userFound = User::where('id', '=', $decodedId)->first();

            $message = "Funcoes desativadas, mas accesso mantido ate a validade da sua sessao";
        } else if ($decodedRole == User::ROLE_ADMIN && $decodedId != $id) {

            $userFound = User::where('id', '=', $id)->first();
            $message = "Funcoes desativadas, mas accesso mantido ate a validade da sessao do usuario";
        } else {
            return $this->generateResponse("Action not allowed", 403);
        }

        if ($userFound->status == false) {
            return $this->generateResponse("Usuario ja Inativado!", 200);
        }

        $userFound->status = false;
        $userFound->save();

        $this->rabbitMQFanOutExge->publish($_ENV['RABBITMQ_FAN_OUT_EXCHANGE_INACT'], ['userId' => $userFound->id]);

        $this->cleanUserCache();
        return $this->generateResponse("Usuario Inativado com Sucesso!", 200, ["message" => $message]);
    }


    public function verifyUser(int $id, string $email): bool
    {
        $user = User::where('id', "=", $id)->where('email', "LIKE", $email)->first();
        if ($user == null) {
            return false;
        } else if (boolval($user->status) == false) {
            return false;
        }
        return true;
    }

    private function setUserCache(array $data)
    {
        $this->redisService->setDataOnCache("userCache", "users", $data);
    }

    private function cleanUserCache()
    {
        $this->redisService->dropCachedData("userCache", "users");
    }


    private function generateResponse(string $message, int $status, ?array $data = null, ?string $token = null): array
    {
        $response = [
            'message' => $message,
            'status' => $status,
        ];
        if (isset($data)) {
            $response['data'] = $data;
        }
        if (isset($token)) {
            $response['token'] = $token;
        }

        return $response;
    }
}