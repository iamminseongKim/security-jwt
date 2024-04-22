package com.example.securityjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 이름 검증
    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey)
                .build().parseSignedClaims(token).getPayload()
                .get("username", String.class);
    }

    // 역할 검증
    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey)
                .build().parseSignedClaims(token).getPayload()
                .get("role", String.class);
    }

    // 만료시간 검증
    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey)
                .build().parseSignedClaims(token)
                .getPayload().getExpiration().before(new Date());
    }

    // access 토큰인지, refresh 토큰인지
    public String getCategory(String token) {
        return Jwts.parser().verifyWith(secretKey).build()
                .parseSignedClaims(token)
                .getPayload()
                .get("category", String.class);
    }

    public String createJwt(String category, String username, String role, Long expiredMs) {
        return Jwts.builder()                                                       // jwt 토큰 만들기
                .claim("category", category)
                .claim("username", username)                                     // username
                .claim("role", role)                                             // role
                .issuedAt(new Date(System.currentTimeMillis()))                     // 생성시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs))       // 만료 시간
                .signWith(secretKey)                                                // 암호화 키
                .compact();                                                         // 발행
    }

}
