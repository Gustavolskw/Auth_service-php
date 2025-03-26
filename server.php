<?php
require_once __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;
use Auth\Router\Routes;
use Auth\Config\Redis;
use OpenSwoole\Http\Server;
use OpenSwoole\Http\Request;
use OpenSwoole\Http\Response;


// Carrega as variáveis de ambiente do arquivo .env
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Verifica se JWT_SECRET está definido
if (!isset($_ENV['JWT_SECRET']) || empty($_ENV['JWT_SECRET'])) {
    die('Erro: A variável de ambiente JWT_SECRET não está definida no .env');
}

try {
    $redis = Redis::getClient();
} catch (\Exception $e) {
    die('Erro ao inicializar o Redis: ' . $e->getMessage());
}


$server = new Server('0.0.0.0', 9501);

$server->on('start', function (Server $server) {
    echo "AuthService running on http://0.0.0.0:9501\n";
});

$server->on('request', function (Request $request, Response $response) {
    $routes = new Routes();
    $routes->handle($request, $response);
});

$server->start();