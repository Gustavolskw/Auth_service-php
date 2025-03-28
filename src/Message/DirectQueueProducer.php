<?php

namespace Auth\Message;

use PhpAmqpLib\Connection\AMQPStreamConnection;
use PhpAmqpLib\Message\AMQPMessage;


class DirectQueueProducer
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

    public function publish(string $queue, array $payload): void
    {
        $this->channel->queue_declare($queue, false, true, false, false);

        $message = new AMQPMessage(json_encode($payload), [
            'delivery_mode' => AMQPMessage::DELIVERY_MODE_PERSISTENT,
            'content_type' => 'application/json'
        ]);

        $this->channel->basic_publish($message, '', $queue);
    }

    public function __destruct()
    {
        $this->channel->close();
        $this->connection->close();
    }
}
