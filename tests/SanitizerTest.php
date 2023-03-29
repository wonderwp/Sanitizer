<?php

namespace WonderWp\Component\Sanitizer;

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

        // test XSS attacks
        $this->assertEquals('', $sanitizedData['name']);
        $this->assertEquals('', $sanitizedData['address']['street']);
        $this->assertEquals('o\&quot; onmouseover=\&quot;alert(1)', $sanitizedData['malicious1']);
        $this->assertEquals('o&quot;+onmouseover&quot;alert1', $sanitizedData['malicious2']);
    }
}
