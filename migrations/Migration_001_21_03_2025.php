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
            $table->integer('role')->default(1);
            $table->boolean('status')->default(true);
        });
    }

    public function down(): void
    {
        Capsule::schema()->dropIfExists('users');
    }
}