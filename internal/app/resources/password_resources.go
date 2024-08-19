package resources

func GeneratePwdAuthPage(msg string) string {
	pwdAuthPage := `
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Zero Trust Service Function Chaining Login Portal</title>
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<link rel="stylesheet" href="/9af1ecf7/password-style.css">
		</head>
		<body>
			<div class="container">
				<h1>Zero Trust Service Function Chaining<br>Login Portal</h1>
				<h2>Password Authentication</h2>
				<h3>` + msg + `</h3>
				<form method="POST">
					<label for="username">Username:</label>
					<input type="text" id="username" name="username" required>
					<label for="password">Password:</label>
					<input type="password" id="password" name="password" required>
					<button type="submit">Log In</button>
				</form>
		</body>
	</html>	`
	return pwdAuthPage
}

var PasswordStyle string = `
body {
	font-family: "Segoe UI", "Roboto", sans-serif;
	background-color: #f2f2f2;
	margin: 0;
}

.container {
	background-color: #fff;
	border-radius: 5px;
	box-shadow: 0 0 20px rgba(0,0,0,0.2);
	margin: 50px auto;
	padding: 30px;
	max-width: 700px;
}

h1 {
	font-size: 36px;
	margin: 0 0 20px;
	text-align: center;
	color: #333;
}

h2 {
	font-size: 24px;
	margin: 0 0 10px;
	text-align: center;
	color: #333;
}

h3 {
	font-size: 18px;
	margin: 0 0 10px;
	text-align: center;
	color: #f44336;
}

form {
	display: flex;
	flex-direction: column;
	align-items: center;
	margin-top: 20px;
}

label {
	font-size: 16px;
	color: #333;
	margin-bottom: 5px;
	text-align: left;
	display: block;
	width: 100%;
}

input[type="text"],
input[type="password"],
#register-username,
#login-username {
	padding: 12px;
	border-radius: 5px;
	border: none;
	background-color: #f2f2f2;
	width: 100%;
	font-size: 16px;
	margin-bottom: 15px;
}

button[type="submit"],
#register-button,
#login-button {
	padding: 12px 20px;
	border-radius: 5px;
	border: none;
	background-color: #4caf50;
	color: #fff;
	font-size: 16px;
	cursor: pointer;
	transition: background-color 0.3s ease-in-out;
}

button[type="submit"]:hover,
#register-button:hover,
#login-button:hover {
	background-color: #3e8e41;
}

.passkey-auth {
	margin-top: 30px;
}
`
