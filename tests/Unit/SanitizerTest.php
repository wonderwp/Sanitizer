<?php

namespace WonderWp\Component\Sanitizer\Tests\Unit;

use WonderWp\Component\Sanitizer\Sanitizer;

use PHPUnit\Framework\TestCase;

class SanitizerTest extends TestCase
{

    public function testSanitizeText()
    {
        $data = "This is <b>bold</b> text";
        $this->assertEquals("This is bold text", Sanitizer::sanitizeText($data));
    }

    public function testSanitizeHtml()
    {
        $data = "<p>This is <b>bold</b> text</p>";
        $this->assertEquals("<p>This is <b>bold</b> text</p>", Sanitizer::sanitizeHtml($data));
    }

    public function testSanitizeEmail()
    {
        $data = "john@example.com";
        $this->assertEquals("john@example.com", Sanitizer::sanitizeEmail($data));
    }

    public function testSanitizeUrl()
    {
        $data = "http://example.com";
        $this->assertEquals("http://example.com", Sanitizer::sanitizeUrl($data));
    }

    public function testSanitizeInteger()
    {
        $data = "123";
        $this->assertEquals(123, Sanitizer::sanitizeInteger($data));
    }

    public function testSanitizeFloat()
    {
        $data = "3.14";
        $this->assertEquals(3.14, Sanitizer::sanitizeFloat($data));
    }

    public function testSanitizeData()
    {
        $data = [
            'name'       => '<script>alert("XSS attack")</script>',
            'email'      => 'john.doe@example.com',
            'url'        => 'https://example.com/',
            'age'        => 30,
            'salary'     => 10000.50,
            'lat'        => '48.8566',
            'lng'        => '2.3522',
            'address'    => [
                'street' => '<script>alert("XSS attack")</script>',
                'city'   => '<b>New York</b>',
                'state'  => 'NY',
                'zip'    => '10001'
            ],
            'phone'      => '+1 (555) 555-5555',
            'malicious1' => 'o\" onmouseover=\"alert(1)',
            'malicious2' => 'o"+onmouseover%3D"alert%281%29'
        ];

        $sanitizedData = Sanitizer::sanitizeData($data);

        $this->assertEquals('john.doe@example.com', $sanitizedData['email']);
        $this->assertEquals('https://example.com/', $sanitizedData['url']);
        $this->assertEquals(30, $sanitizedData['age']);
        $this->assertEquals(10000.5, $sanitizedData['salary']);
        $this->assertEquals('+1 (555) 555-5555', $sanitizedData['phone']);

        $this->assertEquals('New York', $sanitizedData['address']['city']);
        $this->assertEquals('NY', $sanitizedData['address']['state']);
        $this->assertEquals('10001', $sanitizedData['address']['zip']);

        $this->assertEquals(48.8566, $sanitizedData['lat']);
        $this->assertEquals(2.3522, $sanitizedData['lng']);

        // XSS: tags stripped; remaining text is entity-encoded by sanitizeText.
        $this->assertStringNotContainsString('<script>', $sanitizedData['name']);
        $this->assertStringNotContainsString('<script>', $sanitizedData['address']['street']);
        $this->assertStringContainsString('&quot;', $sanitizedData['malicious1']);
        $this->assertStringNotContainsString('<', $sanitizedData['malicious2']);
    }

    public function testSanitizeDataWithActionEditpost()
    {
        $data = [
            '_wpnonce' => '63d16f5e1e',
            '_wp_http_referer' => '/wp/wp-admin/post.php?post=1&action=edit',
            'user_ID' => 1,
            'action' => 'editpost',
            'originalaction' => 'editpost',
            'post_type' => 'post',
            'original_post_status' => 'publish',
            'post_ID' => 9217,
            'meta-box-order-nonce' => '0977cc44da',
            'closedpostboxesnonce' => 'e35d35dced',
            'samplepermalinknonce' => '02c7d2b556',
            'seopanel' => [
                'title' => '',
                'desc'  => '',
                'classes' => '',
                'jsclass' => '',
            ],
            'test_lat' => '43.464276',
            'test_lng' => '3.46911',
            'test_popin_offset' => '50,35',
            'post_mime_type' => '',
            'ID' => 1,
            'post_author' => 1,
            'post_status' => 'publish',
            'comment_status' => 'closed',
            'ping_status' => 'closed',
        ];
        $sanitizedData = Sanitizer::sanitizeData($data);
        $this->assertEquals('43.464276', $sanitizedData['test_lat']);
        $this->assertEquals('3.46911', $sanitizedData['test_lng']);
    }

    public function testSanitizeDataStripsScriptTagsFromNestedStrings(): void
    {
        $out = Sanitizer::sanitizeData([
            'bio' => '<script>alert(1)</script>Hello',
            'nested' => ['note' => '<img src=x onerror=alert(1)>ok'],
        ]);
        $this->assertStringNotContainsString('<script>', $out['bio']);
        $this->assertStringContainsString('Hello', $out['bio']);
    }

    public function testSanitizeDataTreatsNumericStringWithDecimalAsFloat(): void
    {
        $this->assertSame(1.5, Sanitizer::sanitizeData('1.5'));
        $this->assertSame(2, Sanitizer::sanitizeData('2'));
    }

    public function testInstanceSanitizeDelegatesToSanitizeData(): void
    {
        $sanitizer = Sanitizer::getInstance();
        $this->assertSame(42, $sanitizer->sanitize('42'));
    }
}
