<?php
header('Content-Type: application/json');
include "db.php";

session_start();

function sendResponse($status, $message, $data = null) {
    http_response_code($status);
    echo json_encode(['message' => $message, 'data' => $data]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] != 'POST') {
    sendResponse(405, "Method Not Allowed");
}

$input = json_decode(file_get_contents('php://input'), true);

$username = $input['username'] ?? '';
$password = $input['password'] ?? '';

if (empty($username) || empty($password)) {
    sendResponse(400, "Missing required fields");
}

$username = mysqli_real_escape_string($connection, $username);
$password = mysqli_real_escape_string($connection, $password);

$query = "SELECT * FROM users WHERE username = '{$username}'";
$select_user_query = mysqli_query($connection, $query);

if (!$select_user_query) {
    sendResponse(500, "Database query failed");
}

$userData = mysqli_fetch_assoc($select_user_query);

if ($userData && password_verify($password, $userData['password'])) {
    // Successful login
    $_SESSION['id']        = $userData['id'];
    $_SESSION['username']  = $userData['username'];
    $_SESSION['firstname'] = $userData['firstname'];
    $_SESSION['lastname']  = $userData['lastname'];
    $_SESSION['img']       = $userData['img'];
    $_SESSION['email']     = $userData['email'];

    sendResponse(200, "Login successful", $userData);
} else {
    sendResponse(401, "Invalid credentials");
}
?>
