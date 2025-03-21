<?php
require_once __DIR__ . '/vendor/autoload.php';

use Auth\Router\Routes;
use OpenSwoole\Http\Server;
use OpenSwoole\Http\Request;
use OpenSwoole\Http\Response;

$server = new Server('0.0.0.0', 9501);

$server->on('start', function (Server $server) {
    echo "AuthService running on http://0.0.0.0:9501\n";
});

$server->on('request', function (Request $request, Response $response) {
    $routes = new Routes();
    $routes->handle($request, $response);
});

$server->start();