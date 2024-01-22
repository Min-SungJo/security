package com.ride.security;

import com.ride.security.auth.RegisterRequest;
import com.ride.security.auth.AuthenticationService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.redis.core.RedisKeyValueAdapter;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;

import static com.ride.security.member.Role.*;

@SpringBootApplication
@EnableJpaAuditing(auditorAwareRef = "auditorAware")
@EnableRedisRepositories(enableKeyspaceEvents = RedisKeyValueAdapter.EnableKeyspaceEvents.ON_STARTUP)
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService service) {
		return args -> {
			var admin = RegisterRequest.builder()
					.name("admin")
					.email("admin@admin.com")
					.password("pw")
					.role(ADMIN)
					.build();
			System.out.println("ADMIN token: "+service.register(admin).getAccessToken());

			var manager = RegisterRequest.builder()
					.name("manager")
					.email("manager@manager.com")
					.password("pw")
					.role(MANAGER)
					.build();
			System.out.println("manager token: "+service.register(manager).getAccessToken());

		};
	}

}
