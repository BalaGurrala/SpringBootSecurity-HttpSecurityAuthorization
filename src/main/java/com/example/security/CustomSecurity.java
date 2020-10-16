package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class CustomSecurity extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		System.out.println("In Memory Authentication...");
		auth.inMemoryAuthentication()
			.withUser("admin").password("admin").roles("USER", "ADMIN")
			.and()
			.withUser("user").password("user").roles("USER");
	}

	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.httpBasic() 
			.and()
			.authorizeRequests()
			.antMatchers("/user").hasRole("USER")
			.antMatchers("/admin").hasRole("ADMIN")
			.antMatchers(HttpMethod.GET, "/courses/**").hasRole("USER")
			.antMatchers(HttpMethod.DELETE, "/courses/**").hasRole("ADMIN")
			.antMatchers(HttpMethod.POST, "/courses").hasRole("ADMIN")
			.antMatchers(HttpMethod.PUT, "/courses").hasRole("ADMIN")
			.antMatchers("/**").permitAll()
			.and().csrf().disable()
			.formLogin();

		/*http
				// HTTP Basic authentication
				.httpBasic() .and()
				.authorizeRequests().antMatchers("/user").hasRole("USER").antMatchers("/admin").hasRole("ADMIN")
				.antMatchers(HttpMethod.GET, "/courses/**").hasRole("USER")
				.antMatchers(HttpMethod.POST, "/courses").hasRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/courses/**").hasRole("ADMIN")
				.antMatchers(HttpMethod.PATCH, "/courses/**").hasRole("ADMIN")
				.antMatchers(HttpMethod.DELETE, "/courses/**").hasRole("ADMIN")
				.antMatchers("/**").permitAll().and()
				.csrf().disable()
				.formLogin().disable();*/

	}
}
