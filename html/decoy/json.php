<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
$q = isset($_GET['q']) ? (string) $_GET['q'] : '';
$payload = [
    'ok' => true,
    'query' => $q,
    'length' => mb_strlen($q),
    'server' => 'vulnlab-decoy',
];
echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
