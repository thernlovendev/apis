<?php
header('Content-Type: application/json');
include "db.php";
require 'classes/config.php';
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Function to send JSON response
function sendResponse($status, $message, $data = null) {
    http_response_code($status);
    echo json_encode(['message' => $message, 'data' => $data]);
    exit;
}

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] != 'POST') {
    sendResponse(405, "Method Not Allowed");
}

// Get JSON input
$input = json_decode(file_get_contents('php://input'), true);

// Extract and validate inputs
$firstname       = $input['firstname'] ?? '';
$lastname        = $input['lastname'] ?? '';
$email           = $input['email'] ?? '';
$username        = isset($input['username']) ? str_replace(' ', '', strtolower($input['username'])) : '';
$password        = $input['password'] ?? '';
$repeat_password = $input['repeat_password'] ?? '';

// Check required fields
if (empty($username) || empty($firstname) || empty($lastname) || empty($email) || empty($password) || empty($repeat_password)) {
    sendResponse(400, "Missing required fields");
}

// Check if passwords match
if ($password !== $repeat_password) {
    sendResponse(400, "Passwords do not match");
}

// Password strength check (implement your check_password_strength function)
// ...

// Check for existing username or email
$checkQuery = "SELECT * FROM users WHERE username = ? OR email = ?";
$stmt = $connection->prepare($checkQuery);

// Bind parameters for checking
$stmt->bind_param("ss", $username, $email);

// Execute the checking query
if (!$stmt->execute()) {
    $error = $stmt->error;
    sendResponse(500, "Internal Server Error: Execution Failed - " . $error);
}

// Store the result to get the number of rows
$stmt->store_result();

if ($stmt->num_rows > 0) {
    sendResponse(409, "Username or Email already exists");
}

// Sanitize inputs and hash password
$firstname = htmlspecialchars(strip_tags($firstname));
$lastname  = htmlspecialchars(strip_tags($lastname));
$email     = htmlspecialchars(strip_tags($email));
$username  = htmlspecialchars(strip_tags($username));
$password  = password_hash($password, PASSWORD_BCRYPT);

// Generate token
$token = bin2hex(random_bytes(50));

// Insert new user
$insertQuery = "INSERT INTO users (firstname, lastname, email, username, password, token) VALUES (?, ?, ?, ?, ?, ?)";
$insertStmt = $connection->prepare($insertQuery);

// Check if preparation was successful
if ($insertStmt === false) {
    sendResponse(500, "Internal Server Error: " . mysqli_error($connection));
}

// Bind parameters for inserting
$insertStmt->bind_param("ssssss", $firstname, $lastname, $email, $username, $password, $token);

// Execute the insert query
if (!$insertStmt->execute()) {
    $error = $insertStmt->error; // Correct variable name
    sendResponse(500, "Internal Server Error: Execution Failed - " . $error);
}

/* Commented out PHPMailer functionality
$mail = new PHPMailer(true);
try {
    // Server settings
    // ...

    // Recipients
    $mail->setFrom('noreply@example.com', 'Mailer');
    $mail->addAddress($email, $firstname);     // Add a recipient

    // Content
    $mail->isHTML(true);                                  // Set email format to HTML
    $mail->Subject = 'Registration Successful';
    $mail->Body    = 'You have successfully registered.';

    $mail->send();
} catch (Exception $e) {
    // Handle mailer error
    sendResponse(500, "Mailer Error: " . $mail->ErrorInfo);
}
*/

// Successful response
sendResponse(201, "User registered successfully", ['token' => $token]);
?>
