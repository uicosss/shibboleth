#!/usr/bin/env php
<?php

try {
    if (!isset($argv[1])) {
        throw new Exception('Asset path argument required');
    }

    $assetPath = trim($argv[1]);

    if (substr($assetPath, -1) == '/') {
        $assetPath = rtrim($assetPath, '/');
    }

    if (!is_writable($assetPath)) {
        throw new Exception("Asset path is not writable");
    }

    $dir = new DirectoryIterator(__DIR__ . '/../src/Shibboleth/assets');
    foreach ($dir as $file) {
        if (!$file->isDot()) {
            copy($file->getRealPath(), $assetPath . '/' . $file->getFilename());
        }
    }
} catch (Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

