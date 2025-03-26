Aqui está a documentação completa e atualizada do `AuthService`
com todos os componentes revisados, com
os comandos para gerar e rodar migrações, e uma
descrição detalhada de todas as funcionalidades do serviço.

---

### Download do Repositório:

```bash
git clone git@github.com:Gustavolskw/Auth_service-php.git
```

---

### Ambiente:

**Em pode ser no mesmo ambiente ou em um ambiente separado da aplicação reliazar a criação dos seguintes Conâiners docker para ter a conexão com uma base de dados e uma mensageria:**

docker-compose.yml

```dockerfile
version: "4"

services:
  mysql-auth-service:
    image: mysql:8.3.0
    container_name: auth-database
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD:-mysql}
      MYSQL_DATABASE: AUTH_SERVICE
    ports:
      - "3307:3306"
    volumes:
      - ./mysql:/var/lib/mysql
      - ./docker/mysql/init.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      retries: 5
      timeout: 5s
  rabbitmq:
    image: "rabbitmq:3-management"
    container_name: "auth-rabbitmq"
    environment:
      RABBITMQ_DEFAULT_USER: guest
      RABBITMQ_DEFAULT_PASS: guest
      RABBITMQ_DEFAULT_VHOST: /
    ports:
      - "5672:5672" # Porta padrão do RabbitMQ
      - "15672:15672" # Interface de gerenciamento do RabbitMQ
    volumes:
      - rabbitmq-data:/var/lib/rabbitmq
    healthcheck:
      test: ["CMD", "rabbitmqctl", "status"]
      interval: 10s
      retries: 5
      timeout: 5s

volumes:
  rabbitmq-data:
    driver: local

```

**Após a criação dos cainter executar os mesmos:**

se for a primeira vez:

```bash
docker compose up --build
```

para iniciar a aplicação sem visualizar os logs

```bash
docker compose up -d
```

para iniciar a aplicação com a visualização dos logs

```bash
docker compose up
```

para finalizar a execução dos containers sem destruir os mesmos:

```bash
docker compose up stop
```

para derrubar ambos container:

```bash
docker compose up down
```

---

### **Documentação Completa do AuthService**

#### **Objetivo**

O `AuthService` é um microserviço projetado para:

- Registrar usuários no banco de dados (`POST /register`) com validação robusta de entradas usando `illuminate/validation`.
- Buscar um usuário específico por email (`GET /user`).
- Buscar todos os usuários registrados (`GET /users`).
- Proteger rotas específicas por método e URI com autenticação JWT.
- Publicar eventos de registro no RabbitMQ para integração com outros serviços.
- Usar o Eloquent como ORM, DTOs para controle de dados retornados e uma estrutura modular com controllers, serviços e roteamento avançado.

#### **Estrutura do Projeto**

```
AuthService/
├── src/                    # Código fonte do projeto
│   ├── Config/            # Configurações gerais
│   │   └── Database.php   # Configuração do Eloquent
│   ├── Controllers/       # Controladores para processar requisições HTTP
│   │   └── AuthController.php
│   ├── DTO/               # Data Transfer Objects para controle de dados
│   │   └── UserDTO.php
│   ├── Entity/            # Modelos do Eloquent (entidades do banco)
│   │   └── User.php
│   ├── Message/           # Integração com mensageria
│   │   └── RabbitMQProducer.php
│   ├── Router/            # Definição de rotas
│   │   └── Routes.php
│   ├── Services/          # Lógica de negócios
│   │   └── AuthService.php
├── migrations/            # Scripts de migração do banco
│   └── Migration_001_21_03_2025.php
├── .env                   # Variáveis de ambiente
├── composer.json          # Dependências e autoload
├── composer.lock          # Lock file do Composer
├── generate_migration.php # Script para gerar migrações
├── migration_counter.txt  # Contador para nomeação de migrações
├── run_migration.php      # Script para executar migrações
├── server.php             # Servidor Swoole
└── README.md              # Documentação básica (opcional)
```

---

### **Arquivos e Funcionalidades**

#### **1. `.env`**

- **Descrição**: Arquivo de configuração de variáveis de ambiente.
- **Funcionalidade**: Define parâmetros para conexão com banco de dados, RabbitMQ e JWT.
- **Conteúdo**:

  ```env
  DB_HOST=localhost
  DB_PORT=3306
  DB_NAME=Service_database
  DB_USER=root
  DB_PASS=root
  DB_DRIVER=mysql

  RABBITMQ_HOST=localhost
  RABBITMQ_PORT=5672
  RABBITMQ_USER=guest
  RABBITMQ_PASS=guest
  RABBITMQ_VHOST=/
  RABBITMQ_QUEUE=auth_queue

  JWT_SECRET=your_secret_key_here  # Gere com: openssl rand -base64 32
  ```

1. **Copiar o arquivo .env-example e formar o .env**:

   ```bash
   cp .env.example .env
   ```

2. **Gerar uma chave segura para o Jwt**:
   ```bash
   openssl rand -base64 32
   ```

---

#### **2. `composer.json`**

- **Descrição**: Define dependências e configurações de autoload.
- **Funcionalidade**: Garante que todas as bibliotecas necessárias estejam disponíveis e mapeia namespaces.
- **Conteúdo**:
  ```json
  {
    "name": "auth/service",
    "description": "Microservice to authenticate users and registrate them on the database",
    "type": "project",
    "autoload": {
      "psr-4": {
        "Auth\\": "src/",
        "Database\\Migrations\\": "migrations/"
      }
    },
    "authors": [
      {
        "name": "Gustavolskw",
        "email": "gustavolschmidt13@gmail.com"
      }
    ],
    "require": {
      "php": ">=8.0",
      "php-amqplib/php-amqplib": "^3.5",
      "illuminate/database": "^10.0",
      "illuminate/validation": "^10.0",
      "respect/validation": "^2.2",
      "symfony/yaml": "^6.0",
      "openswoole/core": "22.1.5",
      "dompdf/dompdf": "^3.1",
      "vlucas/phpdotenv": "^5.6",
      "firebase/php-jwt": "^6.0"
    },
    "minimum-stability": "stable",
    "scripts": {
      "start": "php server.php"
    }
  }
  ```

#### **3. `src/Config/Database.php`**

- **Descrição**: Configura a conexão com o banco de dados usando Eloquent.
- **Funcionalidade**: Inicializa o Eloquent com base nas variáveis do `.env`.
- **Conteúdo**:

  ```php
  <?php
  namespace Auth\Config;

  use Dotenv\Dotenv;
  use Illuminate\Database\Capsule\Manager as Capsule;

  class Database
  {
      public static function bootEloquent(): void
      {
          $dotenv = Dotenv::createImmutable(__DIR__ . '/../../');
          $dotenv->load();

          $capsule = new Capsule;
          $capsule->addConnection([
              'driver' => $_ENV['DB_DRIVER'],
              'host' => $_ENV['DB_HOST'],
              'port' => $_ENV['DB_PORT'],
              'database' => $_ENV['DB_NAME'],
              'username' => $_ENV['DB_USER'],
              'password' => $_ENV['DB_PASS'],
              'charset' => 'utf8',
              'collation' => 'utf8_unicode_ci',
              'prefix' => '',
          ]);

          $capsule->setAsGlobal();
          $capsule->bootEloquent();
      }
  }
  ```

#### **4. `src/Controllers/AuthController.php`**

- **Descrição**: Processa requisições HTTP e valida entradas antes de chamar serviços.
- **Funcionalidade**: Usa o validador do Laravel para `/register` e retorna DTOs formatados.
- **Métodos**:
  - `register`: Valida e registra um usuário.
  - `getUser`: Busca um usuário por email.
  - `getAllUsers`: Retorna todos os usuários.
- **Conteúdo**:

  ```php
  <?php
  namespace Auth\Controllers;

  use Auth\Services\AuthService;
  use Illuminate\Validation\Factory as ValidationFactory;
  use Illuminate\Translation\ArrayLoader;
  use Illuminate\Translation\Translator;
  use OpenSwoole\Http\Request;
  use OpenSwoole\Http\Response;
  use Auth\DTO\UserDTO;

  class AuthController
  {
      private $authService;
      private $validator;

      public function __construct()
      {
          $this->authService = new AuthService();
          $translator = new Translator(new ArrayLoader(), 'en');
          $this->validator = new ValidationFactory($translator);
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
  }
  ```

#### **5. `src/DTO/UserDTO.php`**

- **Descrição**: Define o formato dos dados retornados ao cliente.
- **Funcionalidade**: Controla quais campos do `User` são expostos.
- **Conteúdo**:

  ```php
  <?php
  namespace Auth\DTO;

  class UserDTO
  {
      public int $id;
      public string $name;
      public string $email;

      public function __construct(int $id, string $name, string $email)
      {
          $this->id = $id;
          $this->name = $name;
          $this->email = $email;
      }

      public function toArray(): array
      {
          return [
              'id' => $this->id,
              'name' => $this->name,
              'email' => $this->email,
          ];
      }

      public static function fromArray(array $data): self
      {
          return new self(
              $data['id'],
              $data['name'],
              $data['email']
          );
      }
  }
  ```

#### **6. `src/Entity/User.php`**

- **Descrição**: Modelo Eloquent para a tabela `users`.
- **Funcionalidade**: Representa a entidade no banco e criptografa a senha.
- **Conteúdo**:

  ```php
  <?php
  namespace Auth\Entity;

  use Illuminate\Database\Eloquent\Model;

  class User extends Model
  {
      protected $table = 'users';
      protected $fillable = ['name', 'email', 'password'];
      public $timestamps = false;

      public function setPasswordAttribute($value)
      {
          $this->attributes['password'] = password_hash($value, PASSWORD_BCRYPT);
      }
  }
  ```

#### **7. `src/Message/RabbitMQProducer.php`**

- **Descrição**: Classe para publicar mensagens no RabbitMQ.
- **Funcionalidade**: Envia eventos para a fila configurada.
- **Conteúdo**:

  ```php
  <?php
  namespace Auth\Message;

  use PhpAmqpLib\Connection\AMQPStreamConnection;
  use PhpAmqpLib\Message\AMQPMessage;

  class RabbitMQProducer
  {
      private $connection;
      private $channel;
      private $queue;

      public function __construct()
      {
          $this->connection = new AMQPStreamConnection(
              $_ENV['RABBITMQ_HOST'],
              $_ENV['RABBITMQ_PORT'],
              $_ENV['RABBITMQ_USER'],
              $_ENV['RABBITMQ_PASS'],
              $_ENV['RABBITMQ_VHOST']
          );
          $this->channel = $this->connection->channel();
          $this->queue = $_ENV['RABBITMQ_QUEUE'];
          $this->channel->queue_declare($this->queue, false, true, false, false);
      }

      public function publish(string $message): void
      {
          $msg = new AMQPMessage($message, ['delivery_mode' => AMQPMessage::DELIVERY_MODE_PERSISTENT]);
          $this->channel->basic_publish($msg, '', $this->queue);
      }

      public function __destruct()
      {
          $this->channel->close();
          $this->connection->close();
      }
  }
  ```

#### **8. `src/Router/Routes.php`**

- **Descrição**: Define e roteia requisições HTTP com proteção granular.
- **Funcionalidade**: Mapeia URIs para métodos do `AuthController`, protege rotas por método e URI com JWT e suporta parâmetros dinâmicos.
- **Conteúdo**:

  ```php
  <?php
  namespace Auth\Router;

  use Auth\Controllers\AuthController;
  use Firebase\JWT\JWT;
  use Firebase\JWT\Key;
  use OpenSwoole\Http\Request;
  use OpenSwoole\Http\Response;

  class Routes
  {
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

      public function handle(Request $request, Response $response): void
      {
          $uri = rtrim($request->server['request_uri'] ?? '/', '/');
          $method = strtoupper($request->server['request_method'] ?? 'GET');

          $routes = [
              'GET' => [
                  '/user' => [AuthController::class, 'getUser'],
                  '/users' => [AuthController::class, 'getAllUsers'],
              ],
              'POST' => [
                  '/register' => [AuthController::class, 'register'],
              ],
          ];

          $protectedRoutes = [
              ['method' => 'GET', 'uri' => '/user'],
              ['method' => 'GET', 'uri' => '/users'],
          ];

          $requiresAuth = false;
          foreach ($protectedRoutes as $protected) {
              $routePattern = preg_replace('/\{([^}]+)\}/', '([^/]+)', $protected['uri']);
              if ($method === $protected['method'] && preg_match("#^$routePattern$#", $uri)) {
                  $requiresAuth = true;
                  break;
              }
          }

          if ($requiresAuth && !$this->validateToken($request)) {
              $response->status(401);
              $response->header('Content-Type', 'application/json');
              $response->end(json_encode(['error' => 'Token inválido ou expirado']));
              return;
          }

          $params = [];
          foreach ($routes[$method] ?? [] as $route => $handler) {
              $routePattern = preg_replace('/\{([^}]+)\}/', '([^/]+)', $route);
              if (preg_match("#^$routePattern$#", $uri, $matches)) {
                  if (count($matches) > 1) {
                      array_shift($matches);
                      $params = $matches;
                  }
                  [$controllerClass, $methodName] = $handler;
                  $controller = new $controllerClass();
                  $controller->$methodName($request, $response, ...$params);
                  return;
              }
          }

          $response->status(404);
          $response->header('Content-Type', 'application/json');
          $response->end(json_encode(['error' => 'Rota não encontrada']));
      }
  }
  ```

#### **9. `src/Services/AuthService.php`**

- **Descrição**: Contém a lógica de negócios do serviço.
- **Funcionalidade**: Gerencia registro e busca de usuários, retornando DTOs.
- **Métodos**:
  - `register`: Registra um usuário e retorna token JWT.
  - `getUserByEmail`: Busca um usuário por email como DTO.
  - `getAllUsers`: Retorna todos os usuários como lista de DTOs.
- **Conteúdo**:

  ```php
  <?php
  namespace Auth\Services;

  use Auth\Config\Database;
  use Auth\DTO\UserDTO;
  use Auth\Entity\User;
  use Auth\Message\RabbitMQProducer;
  use Respect\Validation\Validator as v;
  use Firebase\JWT\JWT;

  class AuthService
  {
      private $rabbitMQProducer;

      public function __construct()
      {
          Database::bootEloquent();
          $this->rabbitMQProducer = new RabbitMQProducer();
      }

      public function register(string $name, string $email, string $password): array
      {
          v::stringType()->notEmpty()->length(1, 255)->assert($name);
          v::email()->notEmpty()->assert($email);
          v::stringType()->notEmpty()->length(6, 255)->assert($password);

          if (User::where('email', $email)->exists()) {
              throw new \Exception('Email already exists');
          }

          $user = User::create([
              'name' => $name,
              'email' => $email,
              'password' => $password,
          ]);

          $payload = [
              'iss' => 'auth_service',
              'sub' => $user->id,
              'email' => $user->email,
              'iat' => time(),
              'exp' => time() + 3600,
          ];
          $token = JWT::encode($payload, $_ENV['JWT_SECRET'], 'HS256');

          $message = json_encode(['event' => 'user_registered', 'user_id' => $user->id]);
          $this->rabbitMQProducer->publish($message);

          return [
              'message' => 'User registered successfully',
              'user_id' => $user->id,
              'token' => $token
          ];
      }

      public function getUserByEmail(string $email): ?array
    {
        $user = User::where('email', $email)->first();
        if (!$user) {
            return null;
        }
        return $user->toArray();
    }

    public function getAllUsers(): array
    {
        return User::all()->toArray();
    }
  }
  ```

#### **10. `migrations/Migration_001_21_03_2025.php`**

- **Descrição**: Script de migração para criar a tabela `users`.
- **Funcionalidade**: Define a estrutura da tabela no banco.
- **Conteúdo**:

  ```php
  <?php
  namespace Database\Migrations;

  use Illuminate\Database\Capsule\Manager as Capsule;
  use Illuminate\Database\Schema\Blueprint;

  class Migration_001_21_03_2025
  {
      public function up(): void
      {
          Capsule::schema()->create('users', function (Blueprint $table) {
              $table->increments('id');
              $table->string('name', 255);
              $table->string('email', 255)->unique();
              $table->string('password', 255);
          });
      }

      public function down(): void
      {
          Capsule::schema()->dropIfExists('users');
      }
  }
  ```

#### **11. `generate_migration.php`**

- **Descrição**: Script para gerar migrações vazias.
- **Funcionalidade**: Cria arquivos de migração com ordem numérica e data.
- **Conteúdo**:

  ```php
  <?php
  require_once 'vendor/autoload.php';

  use Auth\Config\Database;
  use Illuminate\Database\Capsule\Manager as Capsule;

  Database::bootEloquent();

  $migrationsDir = __DIR__ . '/migrations';
  $migrationsNamespace = 'Database\\Migrations';

  $counterFile = __DIR__ . '/migration_counter.txt';
  if (file_exists($counterFile)) {
      $counter = (int) file_get_contents($counterFile);
      $counter++;
  } else {
      $counter = 1;
  }
  file_put_contents($counterFile, $counter);

  $formattedCounter = sprintf("%03d", $counter);
  $date = date('d_m_Y');
  $version = "Migration_{$formattedCounter}_{$date}";
  $className = $migrationsNamespace . '\\' . $version;
  $fileName = $migrationsDir . '/' . $version . '.php';

  if (!is_dir($migrationsDir)) {
      mkdir($migrationsDir, 0755, true);
  }

  $migrationTemplate = <<<PHP
  <?php
  namespace $migrationsNamespace;

  use Illuminate\\Database\\Capsule\\Manager as Capsule;
  use Illuminate\\Database\\Schema\\Blueprint;

  class $version
  {
      public function up(): void
      {
          Capsule::schema()->create('table_name', function (Blueprint \$table) {
              \$table->increments('id');
          });
      }

      public function down(): void
      {
          Capsule::schema()->dropIfExists('table_name');
      }
  }
  PHP;

  file_put_contents($fileName, $migrationTemplate);

  echo "Migração vazia gerada com sucesso: $fileName\n";
  ```

#### **12. `run_migration.php`**

- **Descrição**: Script para executar migrações.
- **Funcionalidade**: Aplica uma migração específica ao banco.
- **Conteúdo**:

  ```php
  <?php
  require_once 'vendor/autoload.php';

  use Auth\Config\Database;

  if ($argc < 2) {
      echo "Uso: php run_migration.php <nome_da_migracao>\n";
      echo "Exemplo: php run_migration.php Migration_001_21_03_2025\n";
      exit(1);
  }

  Database::bootEloquent();

  $migrationName = $argv[1];
  $migrationClass = "Database\\Migrations\\$migrationName";

  if (!class_exists($migrationClass)) {
      echo "Erro: Classe '$migrationClass' não encontrada. Verifique o nome do arquivo em migrations/.\n";
      exit(1);
  }

  $migration = new $migrationClass();
  $migration->up();

  echo "Migração '$migrationName' executada com sucesso!\n";
  ```

#### **13. `server.php`**

- **Descrição**: Servidor HTTP baseado em Swoole.
- **Funcionalidade**: Inicia o servidor e delega requisições ao `Routes`.
- **Conteúdo**:

  ```php
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
  ```

---

### **Comandos para Migrações**

#### **Gerar uma Nova Migração**

- **Comando**:
  ```bash
  php generate_migration.php
  ```
- **Resultado**: Gera um arquivo como `migrations/Migration_002_22_03_2025.php`.
- **Ação**: Edite o arquivo gerado para definir a estrutura da tabela.

#### **Executar uma Migração**

- **Comando**:
  ```bash
  php run_migration.php <nome_da_migracao>
  ```
- **Exemplo**:
  ```bash
  php run_migration.php Migration_001_21_03_2025
  ```
- **Resultado**: Aplica a migração ao banco (ex.: cria a tabela `users`).

#### **Verificar o Banco**

- Conecte-se ao MySQL:
  ```bash
  mysql -h localhost -P 3307 -u root -p
  ```
  - Senha: `mysql`
- Use o banco e veja as tabelas:
  ```sql
  USE AUTH_SERVICE;
  SHOW TABLES;
  DESCRIBE users;
  ```

---

### **Endpoints e Exemplos**

#### **POST /register**

- **Descrição**: Registra um novo usuário com validação de entradas.
- **Acesso**: Público (não protegido por JWT).
- **Parâmetros**: `{"name": "string", "email": "string", "password": "string"}`
- **Validação**:
  - `name`: Obrigatório, string, máximo 255 caracteres.
  - `email`: Obrigatório, email válido, máximo 255 caracteres.
  - `password`: Obrigatório, string, mínimo 6 e máximo 255 caracteres.
- **Resposta**:
  - Sucesso (200): `{"message": "User registered successfully", "user_id": int, "token": "string"}`
  - Erro (400): `{"error": "mensagem"}` (ex.: "The name field is required, The email must be a valid email address")
- **Exemplo**:
  ```bash
  curl -X POST -H "Content-Type: application/json" -d '{"name":"João","email":"joao@example.com","password":"123456"}' http://localhost:9501/register
  ```
  - Erro (payload inválido):
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"name":"","email":"invalid","password":"123"}' http://localhost:9501/register
    ```
    Resposta: `{"error":"The name field is required, The email must be a valid email address, The password must be at least 6 characters"}`

#### **GET /user**

- **Descrição**: Busca um usuário por email.
- **Acesso**: Protegido por JWT (header `Authorization: Bearer <token>`).
- **Parâmetros**: `email` (query string).
- **Resposta**:
  - Sucesso (200): `{"id": int, "name": "string", "email": "string"}`
  - Erro (404): `{"error": "Usuário não encontrado"}`
  - Erro (401): `{"error": "Token inválido ou expirado"}`
- **Exemplo**:
  ```bash
  curl -X GET -H "Authorization: Bearer <token>" "http://localhost:9501/user?email=joao@example.com"
  ```

#### **GET /users**

- **Descrição**: Retorna todos os usuários registrados.
- **Acesso**: Protegido por JWT (header `Authorization: Bearer cidade <token>`).
- **Resposta**:
  - Sucesso (200): `[ {"id": int, "name": "string", "email": "string"}, ... ]`
  - Erro (500): `{"error": "mensagem"}`
  - Erro (401): `{"error": "Token inválido ou expirado"}`
- **Exemplo**:
  ```bash
  curl -X GET -H "Authorization: Bearer <token>" "http://localhost:9501/users"
  ```

---

### **Como Executar**

1. **Instale as Dependências**:
   ```bash
   composer install
   ```
2. **Configure o Banco**:

- Gere a migração (se necessário): `php generate_migration.php`
- Execute a migração inicial: `php run_migration.php Migration_001_21_03_2025`

3. **Inicie o Servidor**:
   ```bash
   php server.php
   ```
4. **Teste os Endpoints**:

- Use os exemplos acima com `curl`.

---

### **Notas**

- **Proteção de Rotas**: A proteção agora é granular, definida por método e URI em `$protectedRoutes`, com suporte a parâmetros dinâmicos para expansão futura.
- **DTOs**: Garantem que apenas dados necessários sejam retornados, protegendo informações sensíveis (ex.: `password`).
- **Escalabilidade**: A estrutura permite adicionar novos endpoints e regras de proteção facilmente.
- **Segurança**: JWT e validação robusta protegem contra acessos não autorizados e entradas inválidas.
- **Validação**: O uso de `illuminate/validation` no `AuthController` substitui parcialmente a validação do `respect/validation` no `AuthService`, mas ambas coexistem para camadas diferentes.
- **Segurança**: O `JWT_SECRET` deve ser único e seguro (gere com `openssl rand -base64 32`).

---

#### Feito por Gustavo Luis Schmidt, GitHub: Gustavolskw, se posisvel deixar um Star no repositório pra ajudar na criação de mais templates de projetos PHP com OpenSwoole!
