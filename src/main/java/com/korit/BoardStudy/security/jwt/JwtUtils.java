package com.korit.BoardStudy.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private final Key KEY;

    public JwtUtils(
            // **주의: 이 값은 개발 환경에서만 임시로 사용하는 것입니다.**
            // 운영 환경에서는 반드시 application.properties 또는 application.yml 파일에
            // jwt.secret 프로퍼티를 정의하여 안전한 비밀 키를 사용해야 합니다.
            // 아래의 'MzIyNzgwZTEyMWE3NDZkZDk1NDg1NTE1NzkzMzI4NDc='는 임시 Base64 인코딩된 값입니다.
            // 이 값을 사용하여 애플리케이션이 실행되는지 확인한 후, 설정 파일에 실제 값을 넣으세요.
            @Value("${jwt.secret:MzIyNzgwZTEyMWE3NDZkZDk1NDg1NTE1NzkzMzI4NDc=}") String secret) {
        KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    public String generateAccessToken(String id) {
        return Jwts.builder()
                .subject("AccessToken")
                .id(id)
                .expiration(new Date(new Date().getTime() + (1000L * 60L * 60L * 24L * 30L)))
                .signWith(KEY)
                .compact();
    }

    public String generateVerifyToken(String id) {
        return Jwts.builder()
                .subject("VerifyToken")
                .id(id)
                .expiration(new Date(new Date().getTime() + (1000L * 60L * 3L)))
                .signWith(KEY)
                .compact();

    }

    public boolean isBearer(String token) {
        if (token == null) {
            return false;
        }
        if (!token.startsWith("Bearer ")) {
            return false;
        }
        return true;
    }

    public String removeBearer(String token) {
        return token.replaceFirst("Bearer ", "");
    }

    public Claims getClaims(String token) {
        JwtParserBuilder jwtParserBuilder = Jwts.parser();
        jwtParserBuilder.setSigningKey(KEY);
        JwtParser jwtParser = jwtParserBuilder.build();
        return jwtParser.parseClaimsJws(token).getBody();
    }
}