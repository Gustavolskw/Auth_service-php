<?php

namespace Auth\Message;

use PhpAmqpLib\Connection\AMQPStreamConnection;
use PhpAmqpLib\Message\AMQPMessage;


class FanoutExchangeProducer
{
    private $channel;
    private $connection;

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
    }

    public function publish(string $exchange, array $payload): void
    {
        $this->channel->exchange_declare($exchange, 'fanout', false, true, false);

        $message = new AMQPMessage(json_encode($payload), [
            'delivery_mode' => AMQPMessage::DELIVERY_MODE_PERSISTENT,
            'content_type' => 'application/json'
        ]);

        $this->channel->basic_publish($message, $exchange);
    }

    public function __destruct()
    {
        $this->channel->close();
        $this->connection->close();
    }
}