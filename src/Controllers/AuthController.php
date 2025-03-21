<?php
namespace Auth\Controllers;

use Auth\Services\AuthService;
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

        // Configuração do validador do Laravel
        $translator = new Translator(new ArrayLoader(), 'en');
        $this->validator = new ValidationFactory($translator);
    }

    public function register(Request $request, Response $response): void
    {
        try {
            $data = json_decode($request->getContent(), true) ?? [];

            // Regras de validação
            $rules = [
                'name' => 'required|string|max:255',
                'email' => 'required|email|max:255',
                'password' => 'required|string|min:6|max:255',
            ];

            // Executa a validação
            $validation = $this->validator->make($data, $rules);
            if ($validation->fails()) {
                $errors = $validation->errors()->all();
                throw new \Exception(implode(', ', $errors));
            }

            $result = $this->authService->register($data['name'], $data['email'], $data['password']);
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

            $userDTO = $this->authService->getUserByEmail($email);
            if (!$userDTO) {
                throw new \Exception('Usuário não encontrado');
            }

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
            $userDTOs = $this->authService->getAllUsers();
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(array_map(fn($dto) => $dto->toArray(), $userDTOs)));
        } catch (\Exception $e) {
            $response->status(500);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(['error' => $e->getMessage()]));
        }
    }
}