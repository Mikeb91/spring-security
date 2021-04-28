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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static com.springsecurity.security.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

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
		.csrf().disable() //This is enable by default, IT IS RECOMMENDED TO USE csrf() technique when 
						  //our server is going to be reached from normal users using browsers. 
		
//		.csrf().csrfTokenRepository(new CookieCsrfTokenRepository()); //this configuration can be use if we want to 
																	  //see the cookie on postman
		
//		.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
		
//		.and()
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
//		.httpBasic();
		.formLogin()
			.loginPage("/login") //This is how we can customize the login page, Check it out on templates/login.hmtl
			.permitAll() 
			.defaultSuccessUrl("/courses", true) //After a success login this is the web page we´re gonna see.
			.passwordParameter("password")
			.usernameParameter("remember-me")
		.and()
		.rememberMe()
			.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) // defaults to 2 weeks  //Token repository when we are using Redis.
			.key("somethingverysecured") // Key used to generate our MD5 encoding and generate the cookie.
			.rememberMeParameter("remember-me")
		.and()
		.logout()
			.logoutUrl("/logout") //This is how it comes by default  //We should avoid using a simple get request for loging out. 
			
			.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) //This is the correct way to configure when definitely we want to use
																			   //the GET method to logout. However, if CSRF is enabled, this wont work,
																			   //because it requires a POST method, and even if CSRF is disabled, the post method
																			   //for logging out is recomended. 
			
			.clearAuthentication(true) // After logout we clean the authentication
			.invalidateHttpSession(true) //after logout we invalidate the httpSession 
			.deleteCookies("JSESSIONID", "remember-me") // we erase the cookies from client browser
			.logoutSuccessUrl("/login"); //Redirect to login page. 
			
			
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
