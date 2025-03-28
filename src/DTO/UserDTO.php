<?php

namespace Auth\DTO;

class UserDTO
{
    public int $id;
    public string $name;
    public string $email;
    public string|int $role;
    public int $status;

    public function __construct(int $id, string $name, string $email, $role, $status)
    {
        $this->id = $id;
        $this->name = $name;
        $this->email = $email;
        $this->role = $role;
        $this->status = $status;
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'role' => $this->role,
            'status' => boolval($this->status),
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self($data['id'], $data['name'], $data['email'], $data['role'], $data['status']);
    }
}