<?php

declare(strict_types=1);

namespace {
    if (!function_exists('sanitize_text_field')) {
        function sanitize_text_field($str)
        {
            return strip_tags((string) $str);
        }
    }

    if (!function_exists('wp_kses_post')) {
        function wp_kses_post($data)
        {
            return (string) $data;
        }
    }

    if (!function_exists('sanitize_email')) {
        function sanitize_email($email)
        {
            return filter_var((string) $email, FILTER_SANITIZE_EMAIL) ?: '';
        }
    }

    if (!function_exists('esc_url')) {
        function esc_url($url)
        {
            return (string) $url;
        }
    }

    if (!function_exists('absint')) {
        function absint($value)
        {
            return abs((int) $value);
        }
    }

    if (!function_exists('is_email')) {
        function is_email($email)
        {
            return (bool) filter_var((string) $email, FILTER_VALIDATE_EMAIL);
        }
    }

    if (!function_exists('get_option')) {
        function get_option($option, $default = false)
        {
            if ($option === 'blog_charset') {
                return 'UTF-8';
            }

            return $default;
        }
    }
}
