package com.codingdojo.models;

import javax.validation.constraints.NotEmpty;

public class UserLogin {
	@NotEmpty(message="El usuario es requerido")
	private String userNameLogin;
	
	@NotEmpty(message="La contraseña es requerida")
	private String passwordLogin;
	
	public UserLogin() {
	}
	
	public UserLogin( String userNameLogin, String passwordLogin) {
		this.userNameLogin = userNameLogin;
		this.passwordLogin = passwordLogin;
	}

	public String getUserNameLogin() {
		return userNameLogin;
	}

	public void setUserNameLogin(String userNameLogin) {
		this.userNameLogin = userNameLogin;
	}

	public String getPasswordLogin() {
		return passwordLogin;
	}

	public void setPasswordLogin(String passwordLogin) {
		this.passwordLogin = passwordLogin;
	}
	
}
