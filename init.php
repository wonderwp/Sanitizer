<?php

use WonderWp\Component\DependencyInjection\Container;
use WonderWp\Component\Sanitizer\Sanitizer;

add_action('wonderwp.loader.load', 'wwp_register_sanitizer_definitions_towards_container', 10, 2);

function wwp_register_sanitizer_definitions_towards_container(Container $container)
{
    //Sanitizer
    $container['wwp.sanitizer'] = function () {
        return Sanitizer::getInstance();
    };
}
