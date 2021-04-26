package com.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.springsecurity.security.ApplicationUserRole.*;
import static com.springsecurity.security.ApplicationUserPermission.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{

	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.csrf().disable() // TODO: I WILL LEARN THIS IN THE NEXT SECTION
		.authorizeRequests()  //queremos autorizar peticiones
		.antMatchers("/", "index", "/css/*", "/js/*").permitAll()
		.antMatchers("/api/**").hasRole(STUDENT.name()) //Protects the end-point with the specified role
		.antMatchers(HttpMethod.DELETE, "management/api/**").hasAuthority(COURSE_WRITE.name())
		.antMatchers(HttpMethod.POST, "management/api/**").hasAuthority(COURSE_WRITE.name())  //PERMISSION BASED AUTH 
		.antMatchers(HttpMethod.PUT, "management/api/**").hasAuthority(COURSE_WRITE.name())   // In this case, the app verifies if the 
		.antMatchers(HttpMethod.GET, "management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())//user has the correct permission
		.anyRequest() //Cualquier request del API
		.authenticated() // Debe estar autenticado
		.and()
		.httpBasic(); //mecanismo de transmisión
	}

	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails annaSmithUser = User.builder()
			.username("annasmith")
			.password(passwordEncoder.encode("password"))
			.roles(STUDENT.name()) //ROLE_STUDENT - Forma en la que spring entiende el role
			.build();
		
		UserDetails lindaUser = User.builder()
			.username("linda")
			.password(passwordEncoder.encode("password123"))
			.roles(ADMIN.name())
			.build();
		
		UserDetails tomUser = User.builder()
				.username("tom")
				.password(passwordEncoder.encode("password123"))
				.roles(ADMINTRAINEE.name()) //ADMINTRAINEE
				.build();
		
		
		return new InMemoryUserDetailsManager(
			annaSmithUser,
			lindaUser,
			tomUser
		);
				
	}
	
	
}
