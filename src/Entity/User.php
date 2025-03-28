<?php
namespace Auth\Entity;

use Illuminate\Database\Eloquent\Model;

/**
 *
 * @property int $id
 * @property string $name
 * @property string $email
 * @property string $password
 * @property int $role
 * @property bool $status
 * @mixin \Illuminate\Database\Eloquent\Model
 * @package Auth\Entity
 */
class User extends Model
{
    protected $table = 'users';
    protected $fillable = ['name', 'email', 'password', 'role', 'status'];
    public $timestamps = false;

    // Valores permitidos para o ENUM
    const ROLE_USER = 1;
    const ROLE_ADMIN = 2;

    public function setPasswordAttribute($value)
    {
        $this->attributes['password'] = password_hash($value, PASSWORD_BCRYPT);
    }
    public function isAdmin(): bool
    {
        return $this->role === self::ROLE_ADMIN;
    }

    public function isUser(): bool
    {
        return $this->role === self::ROLE_USER;
    }
}