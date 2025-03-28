<?php

namespace Auth\DTO;

use Exception;
use OpenSwoole\Http\Response;



class HttpResponse
{
    public function response(mixed $data, int $status, Response $response)
    {
        $response->status($status);
        $response->header('Content-Type', 'application/json');
        $response->end(json_encode($data));
    }

    public function exceptionResponse(Exception $e, Response $response)
    {
        $response->status(400);
        $response->header('Content-Type', 'application/json');
        $response->end(json_encode([
            'error' => $e->getMessage(),
            'code' => $e->getCode(),
            'file' => $e->getFile()
        ]));
    }
}