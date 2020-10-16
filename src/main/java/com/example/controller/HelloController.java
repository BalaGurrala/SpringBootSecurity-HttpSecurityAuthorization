package com.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
	
	@GetMapping("/user")
	public String sayHelloUser() {
		return "Hello User...!!!";
	}
	
	
	@GetMapping("/admin")
	public String getHelloAdmin() {
		return "Hello Admin...!!!";
	}
	
	@GetMapping("/public")
	public String getHelloPublic() {
		return "Hello Public...!!!";
	}
	
	
}
