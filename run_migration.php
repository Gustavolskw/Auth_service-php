<?php
require_once 'vendor/autoload.php';

use Auth\Config\Database;

if ($argc < 2) {
    echo "Uso: php run_migration.php <nome_da_migracao>\n";
    echo "Exemplo: php run_migration.php Migration_001_21_03_2025\n";
    exit(1);
}

Database::bootEloquent();

// Nome da migração passado como argumento
$migrationName = $argv[1];
$migrationClass = "Database\\Migrations\\$migrationName"; // Corrigido para "Migrations" com "M" maiúsculo

if (!class_exists($migrationClass)) {
    echo "Erro: Classe '$migrationClass' não encontrada. Verifique o nome do arquivo em migrations/.\n";
    exit(1);
}

$migration = new $migrationClass();
$migration->up();

echo "Migração '$migrationName' executada com sucesso!\n";