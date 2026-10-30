<?php
declare(strict_types=1);

// 参数只用来选「哪一份固定样例」，不接受路径
$allowed = ['sample' => 'sample.txt'];
$key = isset($_GET['file']) ? (string) $_GET['file'] : 'sample';
$name = $allowed[$key] ?? 'sample.txt';
$path = __DIR__ . '/files/' . $name;

header('Content-Type: text/plain; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $name . '"');
readfile($path);
