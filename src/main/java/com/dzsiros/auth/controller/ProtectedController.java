package com.dzsiros.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ProtectedController {

    @GetMapping("/protected-resource")
    @Operation(summary = "Protected resource", security = @SecurityRequirement(name = "bearerAuth"))
    public String getProtectedResource() {
        return "Some protected resource";
    }

}



