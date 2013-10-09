<?php
include('RSA.php');
//or use with namespace + autoload .
$RSA = new RSA();
$keys = $RSA->generateKeys ('9990454949', '9990450271');
$message="your test message goes here";
$encoded = $RSA->encrypt ($message, 5);
$decoded = $RSA->decrypt ($encoded);
echo "encoded : ".$encoded;
echo "\n<br>";
echo "decoded : ".$decoded;exit;
