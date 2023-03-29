<?php

namespace WonderWp\Component\Sanitizer;

use WonderWp\Component\DependencyInjection\SingletonInterface;
use WonderWp\Component\DependencyInjection\SingletonTrait;

class Sanitizer implements SingletonInterface
{
    use SingletonTrait {
        SingletonTrait::buildInstance as createInstance;
    }

    public static function sanitizeText($data): string
    {
        // The default WordPress sanitization function
        $data = sanitize_text_field($data);
        // We also need to convert special characters to HTML entities
        // because the sanitize_text_field function does not do it and it can be subject to XSS attacks
        $data = htmlspecialchars($data, ENT_QUOTES, get_option('blog_charset'));
        return $data;
    }

    public static function sanitizeHtml($data): string
    {
        return wp_kses_post($data);
    }

    public static function sanitizeEmail($data): string
    {
        return sanitize_email($data);
    }

    public static function sanitizeUrl($data): string
    {
        return esc_url($data);
    }

    public static function sanitizeInteger($data): int
    {
        return absint($data);
    }

    public static function sanitizeFloat($data): float
    {
        return floatval($data);
    }

    public static function sanitizeData(mixed $data): mixed
    {
        if (is_array($data)) {
            foreach ($data as $key => $value) {
                $data[$key] = self::sanitizeData($value);
            }
            return $data;
        } elseif (is_numeric($data)) {
            return is_float($data) ? self::sanitizeFloat($data) : self::sanitizeInteger($data);
        } elseif (is_email($data)) {
            return self::sanitizeEmail($data);
        } elseif (self::isUrl($data)) {
            return self::sanitizeUrl($data);
        } elseif (is_string($data)) {
            return self::sanitizeText($data);
        } else {
            // We couldn't find a proposer sanitization method, so we leave the data as is
            return $data;
        }
    }

    public function sanitize(mixed $data): mixed
    {
        return self::sanitizeData($data);
    }

    protected static function isUrl($url): bool|int
    {
        return preg_match('/^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/', $url);
    }

}
