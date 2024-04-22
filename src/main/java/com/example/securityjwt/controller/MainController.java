package com.example.securityjwt.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
public class MainController {

    @GetMapping("/")
    public String mainP() {
        // 사용자 name 가져오기
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        return "Main Controller : " + name;
    }

    @GetMapping("/role")
    public String roleP() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        return authorities.iterator().next().getAuthority();
    }
}
