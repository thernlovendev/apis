<?php include "db.php"; ?>


<?php
//Import PHPMailer classes into the global namespace
//These must be at the top of your script, not inside a function
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require '../classes/config.php';

require 'vendor/autoload.php';

?>

<?php

session_start();

if (isset($_POST['add_user'])) {
  $firstname       = $_POST['firstname'];
  $lastname        = $_POST['lastname'];
  $email           = $_POST['email'];
  $username        = str_replace(' ', '', strtolower($_POST['username'])); // convert to lowercase and remove spaces
  $password        = $_POST['password'];
  $unhashedPassword        = $_POST['password'];
  $repeat_password = $_POST['repeat_password'];

  $img      = $_FILES['img']['name'];
  $img_temp = $_FILES['img']['tmp_name'];

  move_uploaded_file($img_temp, "../admin/assets/img/avatars/$img");

  $_SESSION['form_data'] = array(
    'firstname' => $firstname,
    'lastname' => $lastname,
    'email' => $email,
    'username' => $username,
    'img' => $img
  );

  if (!empty($username) && !empty($firstname) && !empty($lastname) && !empty($email) && !empty($password) && !empty($repeat_password)) {

    // check if passwords match
    if ($password !== $repeat_password) {
      $message = "Passwords do not match";
    } else {

      // check password strength
      if (!check_password_strength($password)) {
        $pass_modal = true;
      } else {

        // check if username and email already exist
        $query = "SELECT * FROM users WHERE username = '$username' OR email = '$email'";
        $result = mysqli_query($connection, $query);

        if (mysqli_num_rows($result) > 0) {
          $row = mysqli_fetch_assoc($result);
          if ($row['username'] == $username) {
            $message_username = "Username already exists";
          } else {
            $message_email = "Email already exists";
          }
        } else {

          // sanitize inputs
          $firstname = mysqli_real_escape_string($connection, $firstname);
          $lastname  = mysqli_real_escape_string($connection, $lastname);
          $email     = mysqli_real_escape_string($connection, $email);
          $username  = mysqli_real_escape_string($connection, $username);
          $password  = mysqli_real_escape_string($connection, $password);

          // hash password
          $password = password_hash($password, PASSWORD_BCRYPT, array('cost' => 12));

          // generate random values for parent_id, teacher_id, and admin_id columns
          $parent_id  = rand(1, 999);

          // generate token
          $length = 50;
          $token = bin2hex(openssl_random_pseudo_bytes($length));
          $query .= "token = '{$token}', ";

          // Send email notification using PHPMailer
          $mail = new PHPMailer;
          $mail->isSMTP();
          $mail->Host = Config::SMTP_HOST;
          $mail->Username = Config::SMTP_USER;
          $mail->Password = Config::SMTP_PASSWORD;
          $mail->Port = Config::SMTP_PORT;
          $mail->SMTPSecure = 'tls';
          $mail->SMTPAuth = true;
          $mail->isHTML(true);
          $mail->CharSet = 'UTF-8';

          $mail->setFrom('noreply.xogos@gmail.com', 'XOGOS GAMING');
          $mail->addAddress('noreply.xogos@gmail.com');

          $mail->Subject = 'New User Parent';
          $mail->Body = 'New account has been created.';

          // Send the email to the admin
          if (!$mail->send()) {
            echo 'Mailer Error: ' . $mail->ErrorInfo;
          } else {
          }

          // Clear the recipients before sending the second email
          $mail->clearAddresses();

          // Set the recipient and email content for the user
          $email = $_POST['email'];
          $mail->addAddress($email);
          $mail->Subject = 'Welcome to XOGOS GAMING';
          $mail->Body = 'Thank you for signing up to XOGOS GAMING. To continue adding your kids, please click the following link to verify your email: <a href="https://myxogos.com/includes/verify.php?token=' . $token . '">Verify Email</a></p>';

          // Send the email to the user
          if (!$mail->send()) {
            echo 'Mailer Error: ' . $mail->ErrorInfo;
          } else {
          }

          // build SQL query
          
          $query  = "INSERT INTO users(img, firstname, lastname, email, username, password, user_role, token) ";
          $query .= "VALUES('{$img}', '{$firstname}', '{$lastname}', '{$email}', '{$username}', '{$password}', 'user', '{$token}') ";

          
        }
      }
    }
  }
}
?>