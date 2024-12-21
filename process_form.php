<?php
include 'db.php'; 

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'];
    $Refferal Link = $_POST['Refferal Link']
    $email = $_POST['email'];
    $password = $_POST['password'];
    $confirm = $_POST['confirm'];
    $coins = isset($_POST['coins']) ? (int)$_POST['coins'] : 0;

   
    if (empty($name) || empty($email) || empty($password) || empty($confirm)) {
        echo "All fields are required.";
        exit;
    }

    if ($password !== $confirm) {
        echo "Passwords do not match.";
        exit;
    }

    
    try {
        $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE email = :email");
        $stmt->bindParam(':email', $email);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            echo "This email is already registered.";
            exit;
        }

        
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        
        $stmt = $conn->prepare("INSERT INTO users (name, Refferal Link, email, password, coins) VALUES (:name, :Refferal Link, :email, :password, :coins)");
        $stmt->bindParam(':name', $name);
        $stmt->bindParam('Refferal Link', $Refferal Link);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->bindParam(':coins', $coins);
        $stmt->execute();

        echo "Registration successful.";
    } catch (PDOException $e) {
        echo "Error: " . $e->getMessage();
    }
}
?>
