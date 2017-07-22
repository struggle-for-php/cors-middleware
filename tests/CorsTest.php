<?php

/*
 * This file is part of the CORS middleware package
 *
 * Copyright (c) 2016 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/cors-middleware
 *
 */

namespace SfpTest\CorsMiddleware;

use PHPUnit\Framework\TestCase;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\NullLogger;

use Zend\Diactoros\ServerRequest as Request;
use Zend\Diactoros\Response;
use Zend\Diactoros\Uri;

use Sfp\CorsMiddleware\Cors;

class CorsTest extends TestCase
{
    private $delegate;
    private $defaultResponse;

    public function setUp()
    {
        $this->delegate = new class implements DelegateInterface {
            public function process(ServerRequestInterface $request)
            {
               return new \Zend\Diactoros\Response();
            }
        };

        $this->defaultResponse = new Response;
    }


    public function testShouldReturn200ByDefault()
    {
        $request = (new Request())
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET");

        $cors = new Cors([], $this->defaultResponse);

        $response = $cors->process($request, $this->delegate);
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testShouldHaveCorsHeaders()
    {
        $request = (new Request())
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("Origin", "http://www.example.com");

        $cors = new Cors([
            "origin" => "*",
            "methods" => ["GET", "POST", "PUT", "PATCH", "DELETE"],
            "headers.allow" => ["Authorization", "If-Match", "If-Unmodified-Since"],
            "headers.expose" => ["Authorization", "Etag"],
            "credentials" => true,
            "cache" => 86400
        ], $this->defaultResponse);

        $response = $cors->process($request, $this->delegate);
        $this->assertEquals("http://www.example.com", $response->getHeaderLine("Access-Control-Allow-Origin"));
        $this->assertEquals("true", $response->getHeaderLine("Access-Control-Allow-Credentials"));
        $this->assertEquals("Origin", $response->getHeaderLine("Vary"));
        $this->assertEquals("Authorization,Etag", $response->getHeaderLine("Access-Control-Expose-Headers"));
    }

    public function testShouldReturn401WithWrongOrigin()
    {
        $request = (new Request())
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("Origin", "http://www.foo.com");

        $cors = new Cors([
            "origin" => "http://www.example.com",
            "methods" => ["GET", "POST", "PUT", "PATCH", "DELETE"],
            "headers.allow" => ["Authorization", "If-Match", "If-Unmodified-Since"],
            "headers.expose" => ["Authorization", "Etag"],
            "credentials" => true,
            "cache" => 86400
        ], $this->defaultResponse);

        $response = $cors->process($request, $this->delegate);
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testShouldReturn200WithCorrectOrigin()
    {
        $request = (new Request())
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("Origin", "http://mobile.example.com");

        $cors = new Cors([
            "origin" => ["http://www.example.com", "http://mobile.example.com"],
            "methods" => ["GET", "POST", "PUT", "PATCH", "DELETE"],
            "headers.allow" => ["Authorization", "If-Match", "If-Unmodified-Since"],
            "headers.expose" => ["Authorization", "Etag"],
            "credentials" => true,
            "cache" => 86400
        ], $this->defaultResponse);

        $response = $cors->process($request, $this->delegate);
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testShouldReturn401WithWrongMethod()
    {
        $request = (new Request())
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("OPTIONS")
            ->withHeader("Origin", "http://www.example.com")
            ->withHeader("Access-Control-Request-Headers", "Authorization")
            ->withHeader("Access-Control-Request-Method", "PUT");

        $cors = new Cors([
            "origin" => ["*"],
            "methods" => ["GET", "POST", "DELETE"],
            "headers.allow" => ["Authorization", "If-Match", "If-Unmodified-Since"],
            "headers.expose" => ["Authorization", "Etag"],
            "credentials" => true,
            "cache" => 86400
        ], $this->defaultResponse);

        $response = $cors->process($request, $this->delegate);

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testShouldReturn401WithWrongMethodFromFunction()
    {
        $request = (new Request())
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("OPTIONS")
            ->withHeader("Origin", "http://www.example.com")
            ->withHeader("Access-Control-Request-Headers", "Authorization")
            ->withHeader("Access-Control-Request-Method", "PUT");

        $cors = new Cors([
            "origin" => ["*"],
            "methods" => function ($request) {
                return ["GET", "POST", "DELETE"];
            },
            "headers.allow" => ["Authorization", "If-Match", "If-Unmodified-Since"],
            "headers.expose" => ["Authorization", "Etag"],
            "credentials" => true,
            "cache" => 86400
        ], $this->defaultResponse);

        $response = $cors->process($request, $this->delegate);

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testShouldReturn200WithCorrectMethodFromFunction()
    {
        $request = (new Request())
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("OPTIONS")
            ->withHeader("Origin", "http://www.example.com")
            ->withHeader("Access-Control-Request-Headers", "Authorization")
            ->withHeader("Access-Control-Request-Method", "PUT");

        $cors = new Cors([
            "origin" => ["*"],
            "methods" => function ($request) {
                return ["GET", "POST", "DELETE", "PUT"];
            },
            "headers.allow" => ["Authorization", "If-Match", "If-Unmodified-Since"],
            "headers.expose" => ["Authorization", "Etag"],
            "credentials" => true,
            "cache" => 86400
        ], $this->defaultResponse);

        $response = $cors->process($request, $this->delegate);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testShouldReturn401WithWrongHeader()
    {
        $request = (new Request())
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("OPTIONS")
            ->withHeader("Origin", "http://www.example.com")
            ->withHeader("Access-Control-Request-Headers", "X-Nosuch")
            ->withHeader("Access-Control-Request-Method", "PUT");

        $cors = new Cors([
            "origin" => ["*"],
            "methods" => ["GET", "POST", "PUT", "PATCH", "DELETE"],
            "headers.allow" => ["Authorization", "If-Match", "If-Unmodified-Since"],
            "headers.expose" => ["Authorization", "Etag"],
            "credentials" => true,
            "cache" => 86400,
            "error" => function ($analysisResultError) {
                return "ignored";
            }
        ], $this->defaultResponse);

        $response = $cors->process($request, $this->delegate);
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testShouldReturn200WithProperPreflightRequest()
    {
        $request = (new Request())
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("OPTIONS")
            ->withHeader("Origin", "http://www.example.com")
            ->withHeader("Access-Control-Request-Headers", "Authorization")
            ->withHeader("Access-Control-Request-Method", "PUT");

        $cors = new Cors([
            "origin" => ["*"],
            "methods" => ["GET", "POST", "PUT", "PATCH", "DELETE"],
            "headers.allow" => ["Authorization", "If-Match", "If-Unmodified-Since"],
            "headers.expose" => ["Authorization", "Etag"],
            "credentials" => true,
            "cache" => 86400
        ], $this->defaultResponse);

        $response = $cors->process($request, $this->delegate);
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testShouldCallError()
    {
        $request = (new Request())
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("OPTIONS")
            ->withHeader("Origin", "http://www.example.com")
            ->withHeader("Access-Control-Request-Headers", "X-Nosuch")
            ->withHeader("Access-Control-Request-Method", "PUT");

        $logger = new NullLogger;
        $cors = new Cors([
            "logger" => $logger,
            "origin" => ["*"],
            "methods" => ["GET", "POST", "PUT", "PATCH", "DELETE"],
            "headers.allow" => ["Authorization", "If-Match", "If-Unmodified-Since"],
            "headers.expose" => ["Authorization", "Etag"],
            "credentials" => true,
            "cache" => 86400,
            "error" => function ($analysisResultError) {
                $response = new Response;
                $response->getBody()->write("Error");
                return $response;
            }
        ], $this->defaultResponse);


        $response = $cors->process($request, $this->delegate);
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Error", $response->getBody());
    }

    public function testShouldSetAndGetError()
    {
        $cors = new Cors([], $this->defaultResponse);
        $cors->setError(function () {
            return "error";
        });
        $error = $cors->getError();
        $this->assertEquals("error", $error());
    }

    public function testShouldSetAndGetLogger()
    {
        $logger = new NullLogger;
        $cors = new Cors([], $this->defaultResponse);
        $cors->setLogger($logger);
        $this->assertInstanceOf("Psr\Log\NullLogger", $cors->getLogger());
    }
}
