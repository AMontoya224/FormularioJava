package com.codingdojo.models;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table( name= "users" )
public class User {
	@Id
	@GeneratedValue( strategy = GenerationType.IDENTITY )  //auto incremental
	private long id;
	
	@NotNull
	@Size( min=3, max=20, message="El nombre debe tener al menos 3 caracteres" )
	private String firstName;
	
	@NotNull
	@Size( min=3, max=20, message="El apellido debe tener al menos 3 caracteres" )
	private String lastName;
	
	@NotNull
	@Size( min=5, max=20, message="El usuario debe tener al menos 5 caracteres" )
	private String userName;
	
	@NotNull
	@Email(message="Ingrese un correo valido")
	private String email;
	
	@NotNull
	@Size( min=8, max=100, message="La contraseña debe tener al menos 8 caracteres" )
	private String password;
	
	@Transient
	private String confirm;
	
	public User() {
		
	}
	
	public User( String firstName, String lastName, String userName, String email,  String password, String confirm) {
		this.firstName = firstName;
		this.lastName = lastName;
		this.userName = userName;
		this.email = email;
		this.password = password;
		this.confirm = confirm;
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getConfirm() {
		return confirm;
	}

	public void setConfirm(String confirm) {
		this.confirm = confirm;
	}
	
}
