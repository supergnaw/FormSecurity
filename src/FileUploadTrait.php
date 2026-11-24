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

    // Sanitize file input with optional safe move
    public static function sanitizeFiles(array $fileFilter, bool $safeMove = false, ?array $allowedMap = null): array
    {
        $output = [];

        // loop through $_FILES
        foreach ($fileFilter as $inputName => $dir) {
            if (!array_key_exists($inputName, $_FILES)) continue;

            $normalized = self::normalizeFilesArray($_FILES[$inputName]);

            if (array_key_exists('name', $normalized)) {
                // this is a flat array with a single file
                if (!self::allowedFile($normalized)) continue; // this file is not allowed

                $output[$inputName] = $normalized;
            } else {
                // this is a multi-file upload
                $output[$inputName] = [];
                foreach ($normalized as $n => $file) {
                    if (!self::allowedFile($file)) {
                        // this file is not allowed
                        continue;
                    }

                    $output[$inputName][$n] = $file;
                }
            }
        }

        // no moving upload files
        if (!$safeMove) {
            ksort($output);
            return $output;
        }

        // perform a safe file move
        foreach ($output as $key => $file) {
            if (array_key_exists("name", $output[$key])) {
                $output[$key]["safe_filename"] = self::safeUploadMove($output[$key], $fileFilter[$key]);
            } else {
                foreach ($file as $k => $f) {
                    $output[$key][$k]["safe_filename"] = self::safeUploadMove($output[$key][$k], $fileFilter[$key]);
                }
            }
            ksort($output[$key]);
        }

        return $output;
    }

    // Normalizes a multi-file upload array.
    public static function normalizeFilesArray(array $fileUploads): array
    {
        // this is a single-file upload
        if (!is_array($fileUploads["name"])) {
            $fileUploads["error_message"] = self::getUploadErrorMessage($fileUploads["error"]);
            $fileUploads["ext"] = strtolower(pathinfo($fileUploads["name"], PATHINFO_EXTENSION));
            $fileUploads["sha256"] = hash_file('sha256', $fileUploads["tmp_name"]);
            ksort($fileUploads);
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
                if ("tmp_name" === $key) {
                    $normalized[$i]["sha256"] = hash_file('sha256', $fileUploads["tmp_name"][$i]);
                }
                $normalized[$i][$key] = $fileUploads[$key][$i];
            }
            ksort($normalized[$i]);
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
    public static function allowedFile(array $fileUpload, ?array $allowedMap = null): bool
    {
        // default fallback
        $allowedMap = (!$allowedMap) ? self::$allowedMap : $allowedMap;

        // extension allowed?
        $ext = strtolower(pathinfo($fileUpload["name"], PATHINFO_EXTENSION));

        if (!array_key_exists($ext, $allowedMap)) {
            throw new Exception("File extension not allowed.");
        }

        // thanks to whomever made the Fileinfo extension to check real MIME types
        $finfo = new finfo(FILEINFO_MIME_TYPE);

        $mime = $finfo->file($fileUpload["tmp_name"]);

        if (!in_array($mime, self::$allowedMap[$ext])) {
            throw new Exception("MIME type not allowed: {$mime}");
        }

        // extension and MIME type match?
        return in_array($mime, $allowedMap[$ext]);
    }

    // Safely moves a temp file to upload directory.
    public static function safeUploadMove(array $fileUpload, string $uploadDir): ?string
    {
        if (!$fileUpload) return "error: input array missing keys 'tmp_name', 'sha256'";

        // upload file is missing???
        if (!file_exists($fileUpload["tmp_name"])) return "error: upload file missing";

        // make the dir if it does not exist
        if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);

        // check for duplicates
        $duplicate = self::checkUploadDuplicate($fileUpload["sha256"], $uploadDir);
        if ($duplicate) return $duplicate;

        // get the file extension
        $ext = strtolower(pathinfo($fileUpload["name"], PATHINFO_EXTENSION));

        // create a randomly generated filename for security
        $safeFilename = bin2hex(random_bytes(16)) . '.' . $ext;

        // generate the full filepath
        $fullUploadPath = $uploadDir . '/' . $safeFilename;

        // move and return filepath on success or null on failure
        return (move_uploaded_file($fileUpload["tmp_name"], $fullUploadPath))
            ? $fullUploadPath : "error: an unkown error occurred using move_uploaded_file()";
    }

    // Moves temp file in an "unsafe" way
    public static function unsafeUploadMove(string $tempFile, string $destFile, string $uploadDir): ?string
    {
        if (!file_exists($tempFile)) return "error: upload file is missing";

        if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);

        $fullUploadPath = $uploadDir . '/' . $destFile;

        return (move_uploaded_file($tempFile, $fullUploadPath))
            ? $fullUploadPath : "error: an unknown error occurred using move_uploaded_file()";
    }

    // Checks to see if an upload file already exists in the target directory
    private static function checkUploadDuplicate(string $uploadHash, string $uploadDir): bool|string
    {
        foreach (array_diff(scandir($uploadDir), ['.', '..']) as $file) {
            $existingFile = $uploadDir . "/$file";

            // ignore directories
            if (!is_file($existingFile)) continue;

            // check for matching hash and return filename if so
            if (hash_file('sha256', $existingFile) === $uploadHash) return $existingFile;
        }

        // no duplicates so unique file confirmed
        return false;
    }

    // Processes file form upload to safely being saved.
    public static function processFileUpload(
        array  $fileUpload,
        string $uploadDir,
        ?array $allowedMap = null
    ): string
    {
        // ensure the upload completed without errors
        if (!$fileUpload["error"] === UPLOAD_ERR_OK) {
            throw new Exception(self::getUploadErrorMessage($fileUpload["error"]));
        }

        if (!self::allowedFile($fileUpload, $allowedMap)) {
            throw new Exception("File MIME type and extension mismatch.");
        }

        $fullUploadPath = self::safeUploadMove($fileUpload, $uploadDir);

        if (!$fullUploadPath) throw new Exception("Error uploading file.");

        return $fullUploadPath;
    }
}