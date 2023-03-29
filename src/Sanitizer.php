<?php

namespace WonderWp\Component\Sanitizer;

use WonderWp\Component\DependencyInjection\SingletonInterface;
use WonderWp\Component\DependencyInjection\SingletonTrait;

class Sanitizer implements SingletonInterface
{
    use SingletonTrait {
        SingletonTrait::buildInstance as createInstance;
    }

    public static function sanitize_text($data): string
    {
        return sanitize_text_field($data);
    }

    public static function sanitize_html($data): string
    {
        return wp_kses_post($data);
    }

    public static function sanitize_email($data): string
    {
        return sanitize_email($data);
    }

    public static function sanitize_url($data): string
    {
        return esc_url($data);
    }

    public static function sanitize_integer($data): int
    {
        return absint($data);
    }

    public static function sanitize_float($data): float
    {
        return floatval($data);
    }

    public static function sanitize_data(mixed $data): mixed
    {
        if (is_array($data)) {
            foreach ($data as $key => $value) {
                $data[$key] = self::sanitize_data($value);
            }
            return $data;
        } elseif (is_numeric($data)) {
            return is_float($data) ? self::sanitize_float($data) : self::sanitize_integer($data);
        } elseif (is_email($data)) {
            return self::sanitize_email($data);
        } elseif (self::is_url($data)) {
            return self::sanitize_url($data);
        } elseif (is_string($data)) {
            return self::sanitize_text($data);
        } else {
            // We couldn't find a proposer sanitization method, so we leave the data as is
            return $data;
        }
    }

    public function sanitize(mixed $data): mixed
    {
        return self::sanitize($data);
    }

    protected static function is_url($url): bool|int
    {
        return preg_match('/^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/', $url);
    }

}
