<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$file = 'imsi_list.txt';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['new_imsi'])) {
        $new_imsi = htmlspecialchars($_POST['new_imsi']);
        // IMSI is typically a 15-digit number, so we use a regex to validate it
        if (preg_match('/^\d{15}$/', $new_imsi)) {
            file_put_contents($file, $new_imsi . PHP_EOL, FILE_APPEND | LOCK_EX);
        }
    } elseif (isset($_POST['delete_imsi'])) {
        $delete_imsi = htmlspecialchars($_POST['delete_imsi']);
        $imsi_list = file($file, FILE_IGNORE_NEW_LINES);
        if (($key = array_search($delete_imsi, $imsi_list)) !== false) {
            unset($imsi_list[$key]);
            file_put_contents($file, implode(PHP_EOL, $imsi_list) . PHP_EOL);
        }
    }
}

$imsi_list = file_exists($file) ? file($file, FILE_IGNORE_NEW_LINES) : [];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IMSI Manager</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
        }
        .container {
            width: 50%;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            margin-top: 50px;
        }
        h1 {
            text-align: center;
            margin-bottom: 20px;
        }
        form {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
        }
        input[type="text"] {
            width: 70%;
            padding: 10px;
            margin-right: 10px;
        }
        button {
            padding: 10px 20px;
        }
        ul {
            list-style-type: none;
            padding: 0;
        }
        li {
            padding: 10px;
            background-color: #f9f9f9;
            margin-bottom: 5px;
            border: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>IMSI Manager</h1>
        <form action="index.php" method="POST">
            <input type="text" name="new_imsi" placeholder="Enter new IMSI (15 digits)" required>
            <button type="submit">Add IMSI</button>
        </form>
        <ul>
            <?php foreach ($imsi_list as $imsi): ?>
                <li>
                    <?= htmlspecialchars($imsi) ?>
                    <form class="inline" action="index.php" method="POST">
                        <input type="hidden" name="delete_imsi" value="<?= htmlspecialchars($imsi) ?>">
                        <button type="submit">Delete</button>
                    </form>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>
</body>
</html>