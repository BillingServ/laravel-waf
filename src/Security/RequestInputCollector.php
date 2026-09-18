<?php

namespace BillingServ\LaravelWaf\Security;

use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;

final class RequestInputCollector
{
    private bool $truncated = false;

    /** @return array<int, InputValue> */
    public function collect(Request $request): array
    {
        $cached = $request->attributes->get('laravel-waf.input_values');
        if (is_array($cached)) {
            return $cached;
        }

        $this->truncated = false;
        $config = (array) config('laravel-waf.rules.input', []);
        $maxValues = max(1, min(4096, (int) ($config['max_values'] ?? 1024)));
        $maxDepth = max(1, min(12, (int) ($config['max_depth'] ?? 10)));
        $maxValueBytes = max(1, min(1048576, (int) ($config['max_value_bytes'] ?? 65536)));
        $maxTotalBytes = max($maxValueBytes, min(4194304, (int) ($config['max_total_bytes'] ?? 262144)));
        $values = [];
        $totalBytes = 0;

        if (($config['path'] ?? true) === true) {
            $this->add($values, $totalBytes, $maxValues, $maxValueBytes, $maxTotalBytes, new InputValue(
                'path',
                'path',
                $request->getPathInfo(),
            ));
        }

        if (($config['query'] ?? true) === true) {
            $this->walk($values, $totalBytes, $maxValues, $maxValueBytes, $maxTotalBytes, 'query', $request->query->all(), 0, $maxDepth);
        }

        if (($config['body'] ?? true) === true) {
            $body = $request->request->all();
            $contentType = strtolower(trim(explode(';', $request->header('content-type', ''))[0]));
            $isJson = str_ends_with($contentType, '/json') || str_ends_with($contentType, '+json');
            if ($body === [] && $isJson) {
                try {
                    $body = $request->json()->all();
                    if ($body === []) {
                        // Laravel also returns [] for malformed JSON; inspect
                        // that raw content instead of treating it as empty.
                        json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);
                    }
                } catch (\Throwable) {
                    $body = $request->getContent();
                }
            }

            // Multipart framing/file contents are not input fields. JSON is
            // already parsed above, including legitimate empty arrays/objects.
            if ($body === [] && !$isJson && $contentType !== 'multipart/form-data') {
                $body = $request->getContent();
            }

            $this->walk($values, $totalBytes, $maxValues, $maxValueBytes, $maxTotalBytes, 'body', $body, 0, $maxDepth);
        }

        if (($config['route'] ?? true) === true) {
            $route = $request->route();
            if (is_object($route) && method_exists($route, 'parameters')) {
                $this->walk($values, $totalBytes, $maxValues, $maxValueBytes, $maxTotalBytes, 'route', $route->parameters(), 0, $maxDepth);
            }
        }

        // Client-supplied file names are a classic traversal/injection vector.
        if (($config['files'] ?? true) === true) {
            $this->uploads(
                $request,
                $values,
                $totalBytes,
                $maxValues,
                $maxDepth,
                $maxValueBytes,
                $maxTotalBytes,
            );
        }

        if (($config['headers'] ?? false) === true) {
            $this->walk($values, $totalBytes, $maxValues, $maxValueBytes, $maxTotalBytes, 'header', $request->headers->all(), 0, $maxDepth);
        }

        if (($config['cookies'] ?? false) === true) {
            $this->walk($values, $totalBytes, $maxValues, $maxValueBytes, $maxTotalBytes, 'cookie', $request->cookies->all(), 0, $maxDepth);
        }

        $request->attributes->set('laravel-waf.input_values', $values);
        $request->attributes->set('laravel-waf.input_truncated', $this->truncated);

        return $values;
    }

    /**
     * Uploads walk the file tree directly so traversal stops as soon as the
     * collector caps are reached, and each name keeps its nested field path
     * (e.g. "uploads.0") so per-field exclude_fields settings keep working.
     *
     * @param array<int, InputValue> $values
     */
    private function uploads(
        Request $request,
        array &$values,
        int &$totalBytes,
        int $maxValues,
        int $maxDepth,
        int $maxValueBytes,
        int $maxTotalBytes,
    ): void {
        $this->walkUploads(
            $request->allFiles(),
            '',
            $values,
            $totalBytes,
            0,
            $maxValues,
            $maxDepth,
            $maxValueBytes,
            $maxTotalBytes,
        );
    }

    /**
     * @param array<int|string, mixed> $files
     * @param array<int, InputValue> $values
     */
    private function walkUploads(
        array $files,
        string $prefix,
        array &$values,
        int &$totalBytes,
        int $depth,
        int $maxValues,
        int $maxDepth,
        int $maxValueBytes,
        int $maxTotalBytes,
    ): void {
        if ($this->truncated || $files === []) {
            return;
        }

        if ($depth > $maxDepth) {
            $this->truncated = true;

            return;
        }

        foreach ($files as $key => $file) {
            $field = ($prefix === '' ? '' : $prefix.'.').preg_replace('/[^A-Za-z0-9_.:-]/', '_', (string) $key);

            if ($file instanceof UploadedFile) {
                // Browsers control both values; Symfony keeps the basename in
                // getClientOriginalName() and the client-relative directory in
                // getClientOriginalPath(), so inspect them separately.
                $this->add($values, $totalBytes, $maxValues, $maxValueBytes, $maxTotalBytes, new InputValue(
                    'file',
                    $field !== '' ? $field : 'file',
                    $file->getClientOriginalName() ?: 'upload',
                ));

                if (method_exists($file, 'getClientOriginalPath')) {
                    $path = $file->getClientOriginalPath();
                    if (is_string($path) && $path !== '' && $path !== $file->getClientOriginalName()) {
                        $this->add($values, $totalBytes, $maxValues, $maxValueBytes, $maxTotalBytes, new InputValue(
                            'file',
                            $field !== '' ? $field.'.path' : 'file.path',
                            $path,
                        ));
                    }
                }
            } elseif (is_array($file)) {
                $this->walkUploads(
                    $file,
                    $field,
                    $values,
                    $totalBytes,
                    $depth + 1,
                    $maxValues,
                    $maxDepth,
                    $maxValueBytes,
                    $maxTotalBytes,
                );
            }

            if ($this->truncated) {
                return;
            }
        }
    }

    /** @param array<int, InputValue> $values */
    private function walk(
        array &$values,
        int &$totalBytes,
        int $maxValues,
        int $maxValueBytes,
        int $maxTotalBytes,
        string $source,
        mixed $value,
        int $depth,
        int $maxDepth,
        string $field = '',
    ): void {
        if ($this->truncated || $value === '' || $value === [] || (!is_string($value) && !is_array($value))) {
            return;
        }

        if ($depth > $maxDepth) {
            $this->truncated = true;

            return;
        }

        if (is_string($value)) {
            $this->add($values, $totalBytes, $maxValues, $maxValueBytes, $maxTotalBytes, new InputValue(
                $source,
                $field !== '' ? $field : $source,
                $value,
            ));

            return;
        }

        foreach ($value as $key => $nested) {
            $part = is_int($key) ? (string) $key : preg_replace('/[^A-Za-z0-9_.:-]/', '_', (string) $key);
            $nestedField = $field === '' ? (string) $part : $field.'.'.$part;
            $this->walk(
                $values,
                $totalBytes,
                $maxValues,
                $maxValueBytes,
                $maxTotalBytes,
                $source,
                $nested,
                $depth + 1,
                $maxDepth,
                $nestedField,
            );

            if ($this->truncated) {
                return;
            }
        }
    }

    /** @param array<int, InputValue> $values */
    private function add(
        array &$values,
        int &$totalBytes,
        int $maxValues,
        int $maxValueBytes,
        int $maxTotalBytes,
        InputValue $input,
    ): void {
        if ($this->truncated || $input->value === '') {
            return;
        }

        if (count($values) >= $maxValues || $totalBytes >= $maxTotalBytes) {
            $this->truncated = true;

            return;
        }

        $remaining = $maxTotalBytes - $totalBytes;
        $length = min(strlen($input->value), $maxValueBytes, $remaining);
        $this->truncated = strlen($input->value) > $length;
        if ($length < 1) {
            return;
        }

        // Normalization happens exactly here, once per value per request.
        // Every inspection rule then reads the same decoded string instead of
        // re-decoding it once per rule.
        $values[] = new InputValue(
            $input->source,
            $input->field,
            InputNormalizer::normalize(substr($input->value, 0, $length)),
        );
        $totalBytes += $length;
    }
}
