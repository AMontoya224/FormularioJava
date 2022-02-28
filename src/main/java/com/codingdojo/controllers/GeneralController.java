package com.codingdojo.controllers;

import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.codingdojo.models.User;
import com.codingdojo.models.UserLogin;
import com.codingdojo.services.UserService;

@Controller
public class GeneralController {
	@Autowired
	private UserService userService;
	
	@GetMapping("/")
	public String index(Model model) {
		model.addAttribute("newUser", new User());
        model.addAttribute("newLogin", new UserLogin());
		return "index.jsp";
	}
	
	@PostMapping("/register")
	public String register(@Valid @ModelAttribute("newUser") User newUser, 
            			   BindingResult result, Model model, HttpSession session,
            			   RedirectAttributes flash) {
		if( result.hasErrors() ) {
			model.addAttribute("newLogin", new UserLogin());
            return "index.jsp";
		}
		if( ! newUser.getPassword().equals(newUser.getConfirm()) ) {
			flash.addFlashAttribute( "registerError", "Las contraseñas deben ser iguales" );
			return "redirect:/";
			
		}
		String hash = BCrypt.hashpw( newUser.getPassword(), BCrypt.gensalt() );
		newUser.setPassword(hash);
		User registeredUser = userService.insertIntoUsers(newUser);
		session.setAttribute( "firstName", registeredUser.getFirstName() );
		session.setAttribute( "lastName", registeredUser.getLastName() );
		session.setAttribute( "userName", registeredUser.getUserName() );
		return "redirect:/";
	}
	
	@PostMapping("/login")
	public String login(@Valid @ModelAttribute("newLogin") UserLogin newLogin, 
						BindingResult result, Model model, HttpSession session,
						RedirectAttributes flash) {
		if( result.hasErrors() ) {
			model.addAttribute("newUser", new User());
			return "index.jsp";
		}
		User foundUser = userService.selectFromUsuariosWhereUserName(newLogin.getUserNameLogin());
		if( foundUser == null ) {
			flash.addFlashAttribute( "loginError", "El usuario no esta registrado" );
			return "redirect:/";
		}
		else if( BCrypt.checkpw(newLogin.getPasswordLogin(), foundUser.getPassword()) ){
			session.setAttribute( "firstName", foundUser.getFirstName() );
			session.setAttribute( "lastName", foundUser.getLastName() );
			session.setAttribute( "userName", foundUser.getUserName() );
			return "redirect:/";
		}
		else {
			flash.addFlashAttribute( "loginError", "La contraseña es incorrecta" );
			return "redirect:/";
		}
	}
}
