<?php

$db['db_host'] = 'localhost';
$db['db_user'] = 'admin';
$db['db_pass'] = '52a6d848b3a02dec4792ba937d3a98f810a5b446af4da5d1';
$db['db_name'] = 'api_test';

foreach ($db as $key => $value) {

    define(strtoupper($key), $value);
}
$connection = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

//if ($connection) {
  //   echo 'We are connected';
 //}