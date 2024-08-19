package resources

func GenerateWelcomePage(msg string) string {
	welcomePage := `
    <!DOCTYPE html>
    <html>
        <head>
            <meta charset="UTF-8">
            <title>Zero Trust Service Function Chaining</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link rel="stylesheet" href="/9af1ecf7/welcome-style.css">
            <script src="/9af1ecf7/welcome-script.js" defer></script>
        </head>
        <body>
            <div class="container">
                <h1>Zero Trust Service Function Chaining<br>Login Portal</h1>
                <h3>` + msg + `</h3>
                <div class="button-container">
                    <button id="password-auth-button">Password Authentication</button>
                    <button id="passkey-auth-button">Passkey Authentication</button>
                </div>
            </div>
        </body>
    </html>	
    `
	return welcomePage
}

var WelcomeStyle string = `
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

h3 {
    font-size: 18px;
    margin: 0 0 10px;
    text-align: center;
    color: #f44336;
}

.button-container {
    display: flex;
    justify-content: center;
    margin-top: 30px;
}

.button-container button {
    padding: 12px 20px;
    border-radius: 5px;
    border: none;
    background-color: #4caf50;
    color: #fff;
    font-size: 16px;
    cursor: pointer;
    margin: 0 10px;
    transition: background-color 0.3s ease-in-out;
}

.button-container button:hover {
    background-color: #3e8e41;
}
`
var WelcomeScript string = `
function navigateToWebsite(path) {
    window.location.href = path;
}

document.addEventListener('DOMContentLoaded', function() {
    // Attach event listener to the password authentication button
    var passwordAuthButton = document.getElementById('password-auth-button');
    if (passwordAuthButton) {
        passwordAuthButton.addEventListener('click', function() {
            navigateToWebsite('/40d2343b/password-authentication');
        });
    }

    // Attach event listener to the passkey authentication button
    var passkeyAuthButton = document.getElementById('passkey-auth-button');
    if (passkeyAuthButton) {
        passkeyAuthButton.addEventListener('click', function() {
            navigateToWebsite('/40d2343b/passkey-authentication');
        });
    }
});
`
