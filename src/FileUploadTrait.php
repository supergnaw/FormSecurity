<?php

declare(strict_types=1);

namespace Supergnaw\FormSecurity;

use \Exception;
use finfo;

trait FileUploadTrait
{

    public static array $allowedMap = [
        'bmp' => ['image/bmp'],
        'csv' => ['text/csv'],
        'gif' => ['image/gif'],
        'gz' => ['application/x-gzip'],
        'jpeg' => ['image/jpeg'],
        'jpg' => [
            'image/jpeg',
            'image/jpg'
        ],
        'json' => [
            'application/json',
            'text/plain'
        ],
        'mpeg' => ['audio/mpeg'],
        'mp3' => ['audio/mpeg'],
        'mp4' => [
            'audio/mp4',
            'video/mp4'
        ],
        'otf' => ['font/otf'],
        'ogg' => [
            'audio/ogg',
            'video/ogg'
        ],
        'pdf' => ['application/pdf'],
        'png' => ['image/png'],
        'rtf' => [
            'text/rtf',
            'application/rtf',
        ],
        'sfnt' => ['font/sfnt'],
        'sql' => [
            'application/sql',
            'text/plain'
        ],
        'toml' => [
            'application/toml',
            'text/plain',
        ],
        'ttf' => ['font/ttf'],
        'txt' => ['text/plain'],
        'webp' => ['image/webp'],
        'woff' => ['font/woff'],
        'woff2' => ['font/woff2'],
        'xml' => [
            'text/xml',
            'text/plain',
        ],
        'yaml' => [
            'application/yaml',
            'text/plain',
        ],
        'zip' => [
            'application/x-zip-compressed',
            'application/zip',
        ],
    ];

    // Normalizes a multi-file upload array.
    public static function normalizeFilesArray(array $fileUploads): array
    {
        // this is a single-file upload
        if (!is_array($fileUploads["name"])) {
            $fileUploads["error_message"] = self::getUploadErrorMessage($fileUploads["error"]);
            $fileUploads["ext"] = strtolower(pathinfo($fileUploads["name"], PATHINFO_EXTENSION));
            return $fileUploads;
        }

        $normalized = [];
        $fileCount = count($fileUploads['name']);
        $fileKeys = array_keys($fileUploads);

        for ($i = 0; $i < $fileCount; $i++) {
            foreach ($fileKeys as $key) {
                if ("error" === $key) {
                    $normalized[$i]["error_message"] = self::getUploadErrorMessage($fileUploads[$key][$i]);
                }
                if ("name" === $key) {
                    $normalized[$i]["ext"] = strtolower(pathinfo($fileUploads["name"][$i], PATHINFO_EXTENSION));
                }
                $normalized[$i][$key] = $fileUploads[$key][$i];
            }
        }

        return $normalized;
    }

    // Returns an error message based on an upload error code.
    private static function getUploadErrorMessage(int $errorCode): string
    {
        return match ($errorCode) {
            UPLOAD_ERR_OK => '',
            UPLOAD_ERR_INI_SIZE => 'The uploaded file exceeds the upload_max_filesize directive in php.ini.',
            UPLOAD_ERR_FORM_SIZE => 'The uploaded file exceeds the MAX_FILE_SIZE directive specified in the HTML form.',
            UPLOAD_ERR_PARTIAL => 'The uploaded file was only partially uploaded.',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded.',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing a temporary folder on the server.',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
            UPLOAD_ERR_EXTENSION => 'A PHP extension stopped the file upload.',
            default => 'Unknown upload error.',
        };
    }

    // Checks if a file upload is allowed based on a combination of MIME type and file extension.
    public static function allowedFile(array $fileUpload, ?array $extension2Mime = null): bool
    {
        // default fallback
        $allowedMap = (!$extension2Mime) ? self::$allowedMap : $extension2Mime;

        // extension allowed?
        $ext = strtolower(pathinfo($fileUpload["tmp_name"], PATHINFO_EXTENSION));

        if (!array_key_exists($ext, $allowedMap)) {
            throw new Exception("File extension not allowed.");
        }

        // thanks to whomever made the Fileinfo extension to check real MIME types
        $finfo = new finfo(FILEINFO_MIME_TYPE);

        $mime = $finfo->file($fileUpload["name"]);

        if (!in_array($mime, self::$allowedMap[$ext])) {
            throw new Exception("MIME type not allowed: {$mime}");
        }

        // extension and MIME type match?
        return in_array($mime === $allowedMap[$ext], true);
    }

    // Safely moves file from temp directory to upload directory.
    public static function uploadSafeMove(array $fileUpload, string $uploadDir): ?string
    {
        $ext = strtolower(pathinfo($fileUpload["tmp_name"], PATHINFO_EXTENSION));

        $tmpPath = pathinfo($fileUpload["tmp_name"], PATHINFO_DIRNAME);

        $safeFilename = bin2hex(random_bytes(16)) . '.' . $ext;

        $fullUploadPath = $tmpPath . '/' . $safeFilename;

        return (move_uploaded_file($tmpPath, $fullUploadPath)) ? $fullUploadPath : null;
    }

    // Processes file form upload to safely being saved.
    public static function processFileUpload(
        array  $fileUpload,
        string $uploadDir,
        ?array $extension2Mime = null
    ): string
    {
        // ensure the upload completed without errors
        if (!$_FILES["file"]["error"] === UPLOAD_ERR_OK) {
            throw new Exception(self::getUploadErrorMessage($fileUpload["error"]));
        }

        if (!self::allowedFile($fileUpload, $extension2Mime)) {
            throw new Exception("File MIME type and extension mismatch.");
        }

        $fullUploadPath = self::uploadSafeMove($fileUpload, $uploadDir);

        if (!$fullUploadPath) throw new Exception("Error uploading file.");

        return $fullUploadPath;
    }
}