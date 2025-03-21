<?php
namespace Auth\Router;

use Auth\Controllers\AuthController;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use OpenSwoole\Http\Request;
use OpenSwoole\Http\Response;

class Routes
{
    /**
     * Valida o token JWT no header Authorization
     */
    private function validateToken(Request $request): bool
    {
        $authHeader = $request->header['authorization'] ?? '';
        if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            return false;
        }

        $token = $matches[1];
        try {
            $key = new Key($_ENV['JWT_SECRET'], 'HS256');
            JWT::decode($token, $key);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Executa a lógica de roteamento
     */
    public function handle(Request $request, Response $response): void
    {
        $uri = rtrim($request->server['request_uri'] ?? '/', '/');
        $method = strtoupper($request->server['request_method'] ?? 'GET');

        // Definição das rotas
        $routes = [
            'GET' => [
                '/user' => [AuthController::class, 'getUser'],  // Busca usuário por email
                '/users' => [AuthController::class, 'getAllUsers'],  // Novo: busca todos os usuários
            ],
            'POST' => [
                '/register' => [AuthController::class, 'register'],  // Registro de usuário
            ],
        ];

        // Rotas protegidas por JWT
        $protectedRoutes = ['/user'];

        // Verifica se a rota existe e aplica o middleware JWT se necessário
        if (isset($routes[$method][$uri])) {
            [$controllerClass, $methodName] = $routes[$method][$uri];

            // Aplica validação JWT para rotas protegidas
            if (in_array($uri, $protectedRoutes) && !$this->validateToken($request)) {
                $response->status(401);
                $response->header('Content-Type', 'application/json');
                $response->end(json_encode(['error' => 'Unauthorized']));
                return;
            }

            $controller = new $controllerClass();
            $controller->$methodName($request, $response);
        } else {
            $response->status(404);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(['error' => 'Rota não encontrada']));
        }
    }
}