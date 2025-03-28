<?php
namespace Auth\Router;

use Auth\Controllers\AuthController;
use Auth\DTO\HttpResponse;
use Auth\Entity\User;
use Auth\JWT\UtilJwt;
use OpenSwoole\Http\Request;
use OpenSwoole\Http\Response;

class Routes
{

    private $utilJwt;
    private $httpResponse;

    public function __construct()
    {
        $this->utilJwt = new UtilJwt();
        $this->httpResponse = new HttpResponse();
    }
    private function validateToken(Request $request): bool
    {
        $authHeader = $request->header['authorization'] ?? '';
        if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            return false;
        }

        $token = $matches[1];
        try {
            $decoded = $this->utilJwt->decodeJwt($token);
            $request->user_id = $decoded->sub;
            return true;
        } catch (\Exception $e) {
            error_log($e->getMessage());
            return false;
        }
    }

    private function validateAcessToRoute(Request $request, int $requiredRole): bool
    {
        $authHeader = $request->header['authorization'] ?? '';
        if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            return false;
        }
        $token = $matches[1];
        try {
            $decoded = $this->utilJwt->decodeJwt($token);
            $role = $decoded->role ?? null;
            return $role >= $requiredRole;
        } catch (\Exception $e) {
            return false;
        }
    }

    public function handle(Request $request, Response $response): void
    {
        $uri = rtrim($request->server['request_uri'] ?? '/', '/');
        $method = strtoupper($request->server['request_method'] ?? 'GET');

        $routes = [
            'GET' => [
                '/user' => [AuthController::class, 'getUser'],
                '/user/{id}' => [AuthController::class, 'getUserById'],
                '/users' => [AuthController::class, 'getAllUsers'],
                '/user/verify/{id}' => [AuthController::class, 'verifyUser']
            ],
            'POST' => [
                '/register' => [AuthController::class, 'register'],
                '/login' => [AuthController::class, 'login'],
            ],
            'PUT' => [
                '/user/{id}' => [AuthController::class, 'update'],
            ],
            'DELETE' => [
                '/user/{id}' => [AuthController::class, 'remove'],
            ],
        ];
        $protectedRoutes = [
            ['method' => 'GET', 'uri' => '/user', 'role' => User::ROLE_USER],
            ['method' => 'GET', 'uri' => '/user/{id}', 'role' => User::ROLE_ADMIN],
            ['method' => 'GET', 'uri' => '/users', 'role' => User::ROLE_ADMIN],
            ['method' => 'PUT', 'uri' => '/user/{id}', 'role' => User::ROLE_USER],
            ['method' => 'DELETE', 'uri' => '/user/{id}', 'role' => User::ROLE_USER],
        ];

        $requiresAuth = false;
        $requiredRole = null;
        foreach ($protectedRoutes as $protected) {
            $routePattern = preg_replace('/\{([^}]+)\}/', '([^/]+)', $protected['uri']);
            if ($method === $protected['method'] && preg_match("#^$routePattern$#", $uri)) {
                $requiresAuth = true;
                $requiredRole = $protected['role'];
                break;
            }
        }

        if ($requiresAuth) {
            if (!$this->validateToken($request)) {
                $this->httpResponse->response(['error' => 'Token inválido ou expirado'], 401, $response);
                return;
            }
            if (!$this->validateAcessToRoute($request, $requiredRole)) {
                $this->httpResponse->response(['error' => 'Acesso negado: cargo insuficiente'], 403, $response);
                return;
            }
        }

        $params = [];
        foreach ($routes[$method] ?? [] as $route => $handler) {
            $routePattern = preg_replace('/\{([^}]+)\}/', '([^/]+)', $route);
            if (preg_match("#^$routePattern$#", $uri, $matches)) {
                if (count($matches) > 1) {
                    array_shift($matches); // Remove o match completo, mantém apenas os grupos
                    $params = $matches;    // $params[0] será o ID
                }
                [$controllerClass, $methodName] = $handler;
                $controller = new $controllerClass();
                $controller->$methodName($request, $response, ...$params);
                return;
            }
        }


        $this->httpResponse->response(['error' => 'Rota não encontrada'], 404, $response);
    }
}