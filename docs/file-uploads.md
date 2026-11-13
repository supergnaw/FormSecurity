# File Upload Security

## Overview

FormSecurity provides helper methods to aid in processing file uploads.

- Normalizing complex `$_FILES` arrays
- Validating uploaded file extensions with [MIME](https://www.iana.org/assignments/media-types) types
- Safely moving uploaded files
- Processing uploaded files using a consistent workflow

> **Note**
>
> File validation is performed using the Fileinfo extension's detected
> MIME type rather than trusting the value supplied by the browser.

| Method                                    | Purpose                                                                                    |
|-------------------------------------------|--------------------------------------------------------------------------------------------|
| `normalizeFilesArray(array $fileUploads)` | Normalizes a multi-file upload array.                                                      |
| `allowedFile(array $fileUpload)`          | Checks if a file upload is allowed based on a combination of MIME type and file extension. |
| `uploadSafeMove(array $fileUpload)`       | Safely moves an uploaded file from the temporary upload location to its final destination. |
| `processFileUpload(array $fileUpload)`    | Processes an uploaded file, validates it, and safely stores it on disk.                    |

### Examples

A method built to easily process and validate file uploads is `processFileUpload()` which verifies the MIME against the
extension, creates a secure upload name, and moves it to the specified location.

```php
$uploadDir = '\path\to\upload\dir';
$fileUpload = $_FILES['file_upload_input'];
$fullUploadPath = FormSecurity::processFileUpload($fileUpload, $uploadDir);
```

> **Important**
>
> Uploaded files are assigned a secure generated filename before being
> written to disk. Do not rely on the original client filename being
> preserved.

When using a multi-file upload, the resulting array in $_FILES is collated, but this can be normalized with
`normalizeFilesArray()`, which also conveniently includes any upload error messages:

```php
// Simplified representation of a multi-file upload.

$_FILES = [
    'multi-file-upload' => [
        'name' => [...],
        'type' => [...],
        'tmp_name' => [...],
        'error' => [...],
        'size' => [...],
    ]
];

$files = FormSecurity::normalizeFilesArray($_FILES);

echo $files;

//  $files = [
//      'multi-file-upload' => [
//          0 => [
//              'ext' => 'png',
//              'name' => 'file01.png',
//              'full_path' => 'file01.png',
//              'type' => 'image/png',
//              'tmp_name' => '\tmp\path\php6338.tmp',
//              'error_message' => 'The uploaded file was only partially uploaded.',
//              'error' => 3,
//              'size' => 1223047,
//          ],
//          1 => [
//              'ext' => 'png',
//              'name' => 'file02.png',
//              'full_path' => 'file02.png',
//              'type' => 'image/png',
//              'tmp_name' => '\tmp\path\php6349.tmp',
//              'error_message' => '',
//              'error' => 0,
//              'size' => 816063,
//          ],
//      ]
//  ];
```
