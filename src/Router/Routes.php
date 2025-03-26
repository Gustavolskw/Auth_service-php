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
     * Valida o token JWT e adiciona informações ao request
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
            $decoded = JWT::decode($token, $key);
            $request->user_id = $decoded->sub;
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

        $routes = [
            'GET' => [
                '/user' => [AuthController::class, 'getUser'],
                '/users' => [AuthController::class, 'getAllUsers']
            ],
            'POST' => [
                '/register' => [AuthController::class, 'register'],
                '/login' => [AuthController::class, 'login'],
            ],
            'PUT' => [
                '/user' => [AuthController::class, 'update'],
            ],
            'DELETE' => [
                '/user' => [AuthController::class, 'remove'],
            ],
        ];

        // Rotas protegidas (método e URI)
        $protectedRoutes = [
            ['method' => 'GET', 'uri' => '/user'],
            ['method' => 'PUT', 'uri' => '/user'], // Inclui o padrão dinâmico
            ['method' => 'DELETE', 'uri' => '/user'],
        ];

        // Verifica se a rota atual requer autenticação
        $requiresAuth = false;
        foreach ($protectedRoutes as $protected) {
            $routePattern = preg_replace('/\{([^}]+)\}/', '([^/]+)', $protected['uri']);
            if ($method === $protected['method'] && preg_match("#^$routePattern$#", $uri)) {
                $requiresAuth = true;
                break;
            }
        }

        // Aplica validação de token para rotas protegidas
        if ($requiresAuth && !$this->validateToken($request)) {
            $response->status(401);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode(['error' => 'Token inválido ou expirado']));
            return;
        }

        // Processa as rotas
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
                $controller->$methodName($request, $response, ...$params); // Passa os parâmetros
                return;
            }
        }

        $response->status(404);
        $response->header('Content-Type', 'application/json');
        $response->end(json_encode(['error' => 'Rota não encontrada']));
    }
}