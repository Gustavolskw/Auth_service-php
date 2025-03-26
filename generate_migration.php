<?php
require_once 'vendor/autoload.php';

use Auth\Config\Database;
use Illuminate\Database\Capsule\Manager as Capsule;

// Carregar o Eloquent
Database::bootEloquent();

// Diretório para armazenar migrações
$migrationsDir = __DIR__ . '/migrations';
$migrationsNamespace = 'Database\\Migrations';

// Arquivo para rastrear o contador de migrações
$counterFile = __DIR__ . '/migration_counter.txt';

// Obter o próximo número incremental
if (file_exists($counterFile)) {
    $counter = (int) file_get_contents($counterFile);
    $counter++;
} else {
    $counter = 1; // Começa em 001 se o arquivo não existir
}
file_put_contents($counterFile, $counter);

// Formatar o número com 3 dígitos (ex.: 001, 002, etc.)
$formattedCounter = sprintf("%03d", $counter);

// Gerar a data no formato D/M/ANO (ex.: 21_03_2025)
$date = date('d_m_Y');

// Nome da migração
$version = "Migration_{$formattedCounter}_{$date}";
$className = $migrationsNamespace . '\\' . $version;
$fileName = $migrationsDir . '/' . $version . '.php';

// Certificar-se de que o diretório migrations existe
if (!is_dir($migrationsDir)) {
    mkdir($migrationsDir, 0755, true);
}

// Template da migração vazia
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
            // Adicione suas colunas aqui
            \$table->increments('id');
        });
    }

    public function down(): void
    {
        Capsule::schema()->dropIfExists('table_name');
    }
}
PHP;

// Escrever o arquivo de migração
file_put_contents($fileName, $migrationTemplate);

echo "Migração vazia gerada com sucesso: $fileName\n";