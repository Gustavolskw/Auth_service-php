<?php
namespace Auth\Controllers;

use Auth\Entity\User;
use Auth\Services\AuthService;
use Auth\Translations\ValidationMessages;
use Exception;
use Illuminate\Validation\Factory as ValidationFactory;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use OpenSwoole\Http\Request;
use OpenSwoole\Http\Response;
use Auth\DTO\HttpResponse;


class AuthController
{
    private $authService;
    private $validator;

    private $resp;


    public function __construct()
    {
        $this->authService = new AuthService();
        $loader = new ArrayLoader();
        $translator = new Translator($loader, 'en');
        $this->validator = new ValidationFactory($translator);
        $this->resp = new HttpResponse();

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
                $this->resp->response(['error' => $validation->errors()->all()], 422, $response);
                return;
            }

            $valData = $validation->validated();

            $result = $this->authService->loginUser($valData['email'], $valData['password']);

            if ($result['status'] === 401) {
                $this->resp->response(['error' => $result['message']], 401, $response);
                return;
            }

            $this->resp->response($result, 200, $response);
        } catch (Exception $e) {
            $this->resp->exceptionResponse($e, $response);
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
                'role' => 'sometimes|in:1,2',
            ];

            $validation = $this->validator->make($data, $rules, ValidationMessages::getMessages());
            if ($validation->fails()) {
                $this->resp->response(['error' => $validation->errors()->all()], 422, $response);
                return;
            }

            $valData = $validation->validated();


            $role = $valData['role'] ?? User::ROLE_USER;
            $result = $this->authService->register($valData['name'], $valData['email'], $valData['password'], (int) $role);

            $this->resp->response($result, 201, $response);

        } catch (Exception $e) {
            $this->resp->exceptionResponse($e, $response);
        }
    }

    public function getUser(Request $request, Response $response): void
    {
        try {
            $data = json_decode($request->getContent(), true) ?? [];
            $rules = [
                'email' => 'required|email|max:255',
            ];

            $validation = $this->validator->make($data, $rules, ValidationMessages::getMessages());
            if ($validation->fails()) {
                $this->resp->response(['error' => $validation->errors()->all()], 422, $response);
                return;
            }
            $valData = $validation->validated();

            $result = $this->authService->getUserByEmail($valData['email']);

            if ($result['status'] == 404) {
                $this->resp->response(['error' => $result['message']], $result['status'], $response);
                return;
            }

            $this->resp->response($result, 200, $response);

        } catch (Exception $e) {
            $this->resp->exceptionResponse($e, $response);
        }
    }

    public function getAllUsers(Request $request, Response $response): void
    {
        try {
            $result = $this->authService->getAllUsers();
            if ($result['status'] != 200) {
                $this->resp->response(['error' => $result['message']], $result['status'], $response);
            }

            $this->resp->response($result, 200, $response);
        } catch (Exception $e) {
            $this->resp->exceptionResponse($e, $response);
        }
    }

    public function update(Request $request, Response $response, int $id)
    {
        try {
            $data = json_decode($request->getContent(), true) ?? [];
            $data += ['id' => $id]; // Ensure 'id' is present in the data

            $rules = [
                'name' => 'sometimes|string|max:255',
                'email' => 'sometimes|email|max:255',
                'password' => 'sometimes|string|min:6|max:255',
                'role' => 'sometimes|in:1,2',
                'status' => 'sometimes|boolean',
                'id' => 'required|integer',
            ];

            $validation = $this->validator->make($data, $rules, ValidationMessages::getMessages());

            if ($validation->fails()) {
                $this->resp->response(['error' => $validation->errors()->all()], 422, $response);
                return;
            }

            $valData = $validation->validated();


            $authHeader = $request->header['authorization'] ?? '';
            $token = str_replace('Bearer ', '', $authHeader);

            $role = $valData['role'] ?? User::ROLE_USER;
            $name = $valData['name'] ?? null;
            $email = $valData['email'] ?? null;
            $password = $valData['password'] ?? null;
            $status = $valData['status'] ?? null;

            $result = $this->authService->updateUser($token, $id, $name, $email, $password, (int) $role, $status);

            if ($result['status'] != 200) {
                $this->resp->response(['error' => $result['message']], $result['status'], $response);
                return;
            }

            $this->resp->response($result, 200, $response);
        } catch (Exception $e) {
            $this->resp->exceptionResponse($e, $response);
        }
    }


    public function remove(Request $request, Response $response, int $id)
    {

        try {
            $data = json_decode($request->getContent(), true) ?? [];
            $data = ['id' => $id];
            $rules = [
                'id' => 'required|integer',
            ];
            $validation = $this->validator->make($data, $rules, ValidationMessages::getMessages());

            if ($validation->fails()) {
                $this->resp->response(['error' => $validation->errors()->all()], 422, $response);
            }
            $valData = $validation->validated();

            $authHeader = $request->header['authorization'] ?? '';
            $token = str_replace('Bearer ', '', $authHeader);

            $result = $this->authService->removeUser($valData['id'], $token);
            $this->resp->response($result, 200, $response);
        } catch (Exception $e) {
            $this->resp->exceptionResponse($e, $response);
        }
    }

    public function verifyUser(Request $request, Response $response, int $id)
    {
        try {

            $email = $request->get['email'] ?? null;


            $data = ['id' => $id, 'email' => $email];
            $rules = [
                'id' => 'required|integer',
                'email' => 'required|email|max:255',
            ];
            $validation = $this->validator->make($data, $rules, ValidationMessages::getMessages());

            if ($validation->fails()) {
                $this->resp->response(['error' => $validation->errors()->all()], 422, $response);
            }
            $valData = $validation->validated();
            $result = $this->authService->verifyUser($valData['id'], $valData['email']);
            $this->resp->response($result, 200, $response);
        } catch (Exception $e) {
            $this->resp->exceptionResponse($e, $response);
        }
    }
}