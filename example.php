<?php
include('RSA.php');
//or use with namespace + autoload .
$RSA = new RSA();

$message="your test message goes here";
$encoded = $RSA->encrypt ($message, 5);
$decoded = $RSA->decrypt ($encoded);
echo $encoded;
echo "<br>";
echo $decoded;exit;
