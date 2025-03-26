<?php
namespace Auth\Controllers;

use Auth\Services\AuthService;
use Auth\DTO\UserDTO;
use Auth\Translations\ValidationMessages;
use Illuminate\Validation\Factory as ValidationFactory;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use OpenSwoole\Http\Request;
use OpenSwoole\Http\Response;

class AuthController
{
    private $authService;
    private $validator;

    public function __construct()
    {
        $this->authService = new AuthService();
        $loader = new ArrayLoader();
        $translator = new Translator($loader, 'en');
        $this->validator = new ValidationFactory($translator);
    }

    public function login(Request $request, Response $response): void
    {
        try {
            $data = json_decode($request->getContent(), true) ?? [];
            $rules = [
                'email' => 'required|email|max:255',
                'password' => 'required|string|min:6|max:255',
            ];

            $validation = $this->validator->make($data, $rules, ValidationMessages::getMessages());
            if ($validation->fails()) {
                $response->status(422);
                $response->header('Content-Type', 'application/json');
                $response->end(json_encode(['error' => $validation->errors()->all()]));
                return;
            }

            $result = $this->authService->loginUser($data['email'], $data['password']);

            if ($result['status'] === 401) {
                $response->status(401);
                $response->header('Content-Type', 'application/json');
                $response->end(json_encode(['error' => $result['message']]));
                return;
            }

            $response->status(200);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode($result));
        } catch (\Exception $e) {
            $response->status(500);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(['error' => $e->getMessage()]));
        }
    }

    public function register(Request $request, Response $response): void
    {
        try {
            $data = json_decode($request->getContent(), true) ?? [];
            $rules = [
                'name' => 'required|string|max:255',
                'email' => 'required|email|max:255',
                'password' => 'required|string|min:6|max:255',
            ];

            $validation = $this->validator->make($data, $rules, ValidationMessages::getMessages());
            if ($validation->fails()) {
                $response->status(422);
                $response->header('Content-Type', 'application/json');
                $response->end(json_encode(['error' => $validation->errors()->all()]));
                return;
            }

            $result = $this->authService->register($data['name'], $data['email'], $data['password']);
            $response->status(201); // 201 para recurso criado
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode($result));
        } catch (\Exception $e) {
            $response->status(400);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(['error' => $e->getMessage()]));
        }
    }

    public function getUser(Request $request, Response $response): void
    {
        try {
            $email = $request->get['email'] ?? null;
            if (!$email) {
                throw new \Exception('Email é obrigatório');
            }

            $userData = $this->authService->getUserByEmail($email);
            if (!$userData) {
                throw new \Exception('Usuário não encontrado');
            }
            $userDTO = UserDTO::fromArray($userData);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode($userDTO->toArray()));
        } catch (\Exception $e) {
            $response->status(404);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(['error' => $e->getMessage()]));
        }
    }

    public function getAllUsers(Request $request, Response $response): void
    {
        try {
            $users = $this->authService->getAllUsers();
            $userDTOs = array_map(fn($user) => UserDTO::fromArray($user), $users);

            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(array_map(fn($dto) => $dto->toArray(), $userDTOs)));
        } catch (\Exception $e) {
            $response->status(500);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(['error' => $e->getMessage()]));
        }
    }

    public function update(Request $request, Response $response)
    {
        $data = json_decode($request->getContent(), true) ?? [];
        $rules = [
            'email' => 'required|email|max:255',
            'name'=> 'required|string|max:255',
            'password' => 'required|string|min:6|max:255',
        ];
        $validation = $this->validator->make($data, $rules, ValidationMessages::getMessages());

        if ($validation->fails()) {
            $response->status(422);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(['error' => $validation->errors()->all()]));
        }

        try{
            $authHeader = $request->header['authorization'] ?? '';
            $token = str_replace('Bearer ', '', $authHeader);

            $result = $this->authService->updateUser($token, $data['name'], $data['email'], $data['password']);
            if($result['status'] === 422){
                $response->status($result['status']);
                $response->header('Content-Type', 'application/json');
                $response->end(json_encode(['error' => $result['message']]));
                return;
            }
            $response->status(200);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode($result));
        }
        catch(\Exception $e){
            $response->status(400);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(['error' => $e->getMessage(),
                'code' => $e->getCode(),
                'file'=> $e->getFile()]));
        }


    }
}