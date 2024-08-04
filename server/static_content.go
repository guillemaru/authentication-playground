package main

const indexBegin = `
	<!DOCTYPE html>
	<html lang="en">
	<head>
	    <meta charset="UTF-8">
	    <meta name="viewport" content="width=device-width, initial-scale=1.0">
	    <title>Authentication playground</title>
	    <script src="https://unpkg.com/htmx.org/dist/htmx.js"></script>
	</head>
	<body>`
const signupTemplate = `
	    <div id="signupform">
		<h1>Sign up</h1>
		<form hx-post="/signup" hx-target="#signupform" hx-swap="outerHTML">
		    <input type="text" id="username" name="username" placeholder="Username" required><br>
		    <input type="password" id="password" name="password" placeholder="Password" required><br>
		    <input type="submit" value="Submit">
		</form>
		<button hx-get="/servelogin" hx-target="#signupform" hx-swap="outerHTML">Login</button>
	    </div>`
const indexEnd = `
	</body>
	</html>
	`
const loginTemplate = `
	<div id="loginform">
		<h1>Login</h1>
		<form hx-post="/login" hx-target="#loginform" hx-swap="outerHTML">
		    <input type="text" id="username" name="username" placeholder="Username" required><br>
		    <input type="password" id="password" name="password" placeholder="Password" required><br>
		    <input type="submit" value="Submit">
		</form>
	</div>
	`
const invalidCredentialsTemplate = `
	<div id="loginagain">
		<p style="color: red;">Invalid username/password. Please try again.</p>
		<button hx-get="/servelogin" hx-target="#loginagain" hx-swap="outerHTML">Log in</button>
	</div>`

const loggedInTemplate = `
	<div id="loggedindiv">
		<h1>Logged in as {{.Username}}</h1>
		<button hx-post="/logout" hx-target="#loggedindiv" hx-swap="outerHTML">Logout</button>
	</div>`
