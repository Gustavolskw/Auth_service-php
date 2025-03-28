<?php
namespace Auth\Translations;

class ValidationMessages
{
    public static function getMessages(): array
    {
        return [
            'required' => 'O campo :attribute é obrigatório.',
            'email' => 'O campo :attribute deve ser um endereço de email válido.',
            'max' => 'O campo :attribute não pode ter mais de :max caracteres.',
            'min' => 'O campo :attribute deve ter pelo menos :min caracteres.',
            'string' => 'O campo :attribute deve ser uma string.',
            'integer' => 'O campo :attribute deve ser um inteiro.',
            'boolean' => 'O campo :attribute deve ser um Booleano(Verdadeiro ou falso).'
        ];
    }
}