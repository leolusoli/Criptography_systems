
<?php

$connection = new PDO('mysql:host=localhost;dbname=testdb;charset=utf8', 'root', 'prova');
$connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$q = $connection->query('SELECT * FROM chiavi');

?>
