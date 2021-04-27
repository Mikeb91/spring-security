package com.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
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
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{

	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.csrf().disable() 
		.authorizeRequests()  
		.antMatchers("/", "index", "/css/*", "/js/*").permitAll()
		.antMatchers("/api/**").hasRole(STUDENT.name())
		//The order of antMatchers matters. It is sequentially evaluated so if we want to prevent an user
		//accessing for a complete group of endpoints, for example /management/ but we do that at the end
		//of the antMatchers, this user will be able to get all previous endpoints like /management/api/ because
		//it checks in order. 
//		.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) 
//		.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())   
//		.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())    
//		.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name()) 
		//this has been commented because now we are implementing @PreAuthorize. Check StudentManagementController. 
		.anyRequest()
		.authenticated() 
		.and()
		.httpBasic(); 
	}

	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails annaSmithUser = User.builder()
			.username("annasmith")
			.password(passwordEncoder.encode("password"))
//			.roles(STUDENT.name()) //ROLE_STUDENT - Forma en la que spring entiende el role
			.authorities(STUDENT.getGrantedAuthorities())
			.build();
		
		UserDetails lindaUser = User.builder()
			.username("linda")
			.password(passwordEncoder.encode("password123"))
//			.roles(ADMIN.name())//ROLE_ADMIN
			.authorities(ADMIN.getGrantedAuthorities())
			.build();
		
		UserDetails tomUser = User.builder()
			.username("tom")
			.password(passwordEncoder.encode("password123"))
//			.roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
			.authorities(ADMINTRAINEE.getGrantedAuthorities())
			.build();
		
		
		return new InMemoryUserDetailsManager(
			annaSmithUser,
			lindaUser,
			tomUser
		);
				
	}
	
	
}
