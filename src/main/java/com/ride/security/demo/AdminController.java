package com.ride.security.demo;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
@SecurityRequirement(name = "bearerAuth")
public class AdminController {


    @GetMapping
    @PreAuthorize("hasAnyAuthority('admin:read')")
    public String get() {
        return "GET:: admin controller";
    }

    @PostMapping
    @Hidden
    @PreAuthorize("hasAnyAuthority('admin:create')")
    public String post() {
        return "POST:: admin controller";
    }
    @PutMapping
    @Hidden
    @PreAuthorize("hasAnyAuthority('admin:update')")
    public String put() {
        return "PUT:: admin controller";
    }
    @DeleteMapping
    @Hidden
    @PreAuthorize("hasAnyAuthority('admin:delete')")
    public String delete() {
        return "DELETE:: admin controller";
    }
}
