<?php

namespace BillingServ\LaravelWaf\Security;

use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;

final class RequestInputCollector
{
    /** @return array<int, InputValue> */
    public function collect(Request $request): array
    {
        $cached = $request->attributes->get('laravel-waf.input_values');
        if (is_array($cached)) {
            return $cached;
        }

        $config = (array) config('laravel-waf.rules.input', []);
        $maxValues = max(1, min(4096, (int) ($config['max_values'] ?? 256)));
        $maxDepth = max(1, min(12, (int) ($config['max_depth'] ?? 5)));
        $maxValueBytes = max(1, min(1048576, (int) ($config['max_value_bytes'] ?? 8192)));
        $maxTotalBytes = max($maxValueBytes, min(4194304, (int) ($config['max_total_bytes'] ?? 65536)));
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
            if ($body === [] && str_contains(strtolower($request->header('content-type', '')), 'json')) {
                try {
                    $body = $request->json()->all();
                } catch (\Throwable) {
                    $body = [];
                }
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
        if ($depth > $maxDepth) {
            return;
        }

        foreach ($files as $key => $file) {
            if (count($values) >= $maxValues || $totalBytes >= $maxTotalBytes) {
                return;
            }

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

                continue;
            }

            if (is_array($file)) {
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
        if (count($values) >= $maxValues || $totalBytes >= $maxTotalBytes || $depth > $maxDepth) {
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

        if (!is_array($value)) {
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

            if (count($values) >= $maxValues || $totalBytes >= $maxTotalBytes) {
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
        if (count($values) >= $maxValues || $totalBytes >= $maxTotalBytes) {
            return;
        }

        $remaining = $maxTotalBytes - $totalBytes;
        $length = min(strlen($input->value), $maxValueBytes, $remaining);
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
