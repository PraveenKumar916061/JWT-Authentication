package com.example.JWTAuthentication.controller;

import com.example.JWTAuthentication.model.AuthRequest;
import com.example.JWTAuthentication.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/persons")
public class PersonController {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/test1")
    public String test1(){
        return "Hello Everyone...";
    }

    @GetMapping("/test2")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String test2(){
        return "How are you...";
    }

    @PostMapping("/authenticate")
    public String generateToken(@RequestBody AuthRequest authRequest) throws UsernameNotFoundException{
        Authentication authentication =authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(),authRequest.getPassword()));
        if(authentication.isAuthenticated())
             return jwtService.generateToken(authRequest.getUsername());
        else
            throw new UsernameNotFoundException("Invalid username");
    }
}
