<html>
<head><title>Secured Page</title></head>
<body>
	<p>This is a secured page<br />
	User: <sec:ifLoggedIn><sec:username /></sec:ifLoggedIn><sec:ifNotLoggedIn>Not Logged In</sec:ifNotLoggedIn></p>
</body>
</html>