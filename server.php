<?php
require_once __DIR__ . '/vendor/autoload.php';
use Dotenv\Dotenv;
use Auth\Router\Routes;
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

$server = new Server('0.0.0.0', 9501);

// Configure the server to use multi-threading and task workers
$server->set([
    'worker_num' => 4,  // Number of worker processes (default is 1)
    'task_worker_num' => 2, // Number of task workers (for asynchronous processing)
    'daemonize' => false,  // Set to true to run as a daemon (background)
    'max_request' => 10000,  // Maximum number of requests per worker before restarting
]);

// Define the task callback - this is where the background task logic goes
$server->on('task', function (Server $server, $task_id, $worker_id, $data) {
    // Here, you handle the task
    echo "Task {$task_id} is being processed\n";

    // Do something with the task data
    // For example, let's just return the task data as a result
    return "Task {$task_id} finished processing";
});

// Define the finish callback - this is called when a task finishes
$server->on('finish', function (Server $server, $task_id, $data) {
    // Here, you can handle the result of a task
    echo "Task {$task_id} finished with data: {$data}\n";
});

$server->on('start', function (Server $server) {
    echo "AuthService running on http://0.0.0.0:9501\n";
});

$server->on('request', function (Request $request, Response $response) {

    $routes = new Routes();
    $routes->handle($request, $response);
});

$server->start();