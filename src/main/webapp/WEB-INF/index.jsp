<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %> 
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>
			Registration and Login
		</title>
		<link rel="stylesheet" type="text/css" href="/css/style2.css">
		<script type="text/javascript" src="js/app2.js"></script>
	</head>
	<body>
		<header>
			<h1>
				Welcome!
			</h1>
			<h3>
				Join our growing community
			</h3>
		</header>
		<main>
			<div class="container">
				<h1>
					Register
				</h1>
				<form:form method="POST" action="/register" modelAttribute="newUser">
					<div class="justify">
						<form:label path="firstName" for="firstName" class="inp">
							<form:input path="firstName" type="text" class="inp-input" name="firstName" id="firstName" placeholder=" " />
					    	<span class="inp-label">First Name</span>
					  		<span class="inp-focus"></span>
					  		<form:errors path="firstName" class="error"/>
						</form:label>
					</div>
					<div class="justify">
						<form:label path="lastName" for="lastName" class="inp">
							<form:input path="lastName" type="text" class="inp-input" name="lastName" id="lastName" placeholder=" " />
					    	<span class="inp-label">Last Name</span>
					  		<span class="inp-focus"></span>
					  		<form:errors path="lastName" class="error"/>
						</form:label>
					</div>
					<div class="justify">
						<form:label path="userName" for="userName" class="inp">
							<form:input path="userName" type="text" class="inp-input" name="userName" id="userName" placeholder=" " />
					    	<span class="inp-label">User Name</span>
					  		<span class="inp-focus"></span>
					  		<form:errors path="userName" class="error"/>
						</form:label>
					</div>
					<div class="justify">
						<form:label path="email" for="email" class="inp">
							<form:input path="email" type="text" class="inp-input" name="email" id="email" placeholder=" " />
					    	<span class="inp-label">Email</span>
					  		<span class="inp-focus"></span>
					  		<form:errors path="email" class="error"/>
						</form:label>
					</div>
					<div class="justify">
						<form:label path="password" for="password" class="inp">
							<div class="row">
								<form:input path="password" type="password" class="inp-input" name="password" id="password" placeholder=" " />
						    	<span class="inp-label inp-label-P">Password</span>
						  		<span class="inp-focus"></span>
					  			<input type="checkbox" class="checkbox" onclick="password_toggle(this)">
					  		</div>
					  		<form:errors path="password" class="error"/>
						</form:label>
					</div>
					<div class="justify">
						<form:label path="confirm" for="confirm" class="inp">
							<div class="row">
								<form:input path="confirm" type="password" class="inp-input" name="confirm" id="confirm" placeholder=" " />
						    	<span class="inp-label inp-label-P">Confirm Password</span>
						  		<span class="inp-focus"></span>
					  			<input type="checkbox" class="checkbox" onclick="password_toggle(this)">
					  		</div>
					  		<p class="error">
					  			<c:out value="${registerError}"/>
					  		</p>
						</form:label>
					</div>
					<button type="submit" class="submit" >
						Submit
					</button>
				</form:form>
			</div>
			<div class="container-1">
			
			</div>
			<div class="container">
				<h1>
					Login
				</h1>
				<h4>
					<c:out value="${loginError}"/>
				</h4>
				<form:form method="POST" action="/login" modelAttribute="newLogin">
					<div class="justify">
						<form:label path="userNameLogin" for="userNameLogin" class="inp">
							<form:input path="userNameLogin" type="text" class="inp-input" name="userNameLogin" id="userNameLogin" placeholder=" " />
					    	<span class="inp-label">User Name</span>
					  		<span class="inp-focus"></span>
					  		<form:errors path="userNameLogin" class="error"/>
						</form:label>
					</div>
					<div class="justify">
						<form:label path="passwordLogin" for="passwordLogin" class="inp">
							<div class="row">
								<form:input path="passwordLogin" type="password" class="inp-input" name="passwordLogin" id="passwordLogin" placeholder=" " />
						    	<span class="inp-label inp-label-P">Password</span>
						  		<span class="inp-focus"></span>
					  			<input type="checkbox" class="checkbox" onclick="password_toggle(this)">
					  		</div>
					  		<form:errors path="passwordLogin" class="error"/>
						</form:label>
					</div>
					<button type="submit" class="submit" >
						Submit
					</button>
				</form:form>
			</div>
		</main>
		<footer>
			<p>
                Developed by <a href="https://github.com/AMontoya224" target="_blank">Andres Montoya</a> 
            </p>
		</footer>
	</body>
</html>