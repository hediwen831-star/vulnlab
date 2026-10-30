<?php
declare(strict_types=1);
require __DIR__ . '/_shell.php';

$allowed = [
    'home' => 'index.php',
    'docs' => '../index.php',
];
$to = isset($_GET['to']) ? (string) $_GET['to'] : 'home';
$target = $allowed[$to] ?? $allowed['home'];
header('Location: ' . $target, true, 302);
exit;
