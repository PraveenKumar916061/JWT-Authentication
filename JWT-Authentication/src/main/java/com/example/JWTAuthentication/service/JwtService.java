package com.example.JWTAuthentication.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {

    public final static String SECRET_KEY="rPZKcsE40PrVG/Kp5Dn2XJy4ljVunXQtt+95BOQuhT9hyD3G7bniJUfLzmxqsSqUtbYMlLUWG/aGzZqZb9wGp4r1LPE24ThgavpcJ9liqztP8SVJnJmujqt74QN0QwewGhopGgcSVkMQeAH2dJ/ZYXrViJznd/ldCLKxjFTvTw2rPbstAcEpGr5Ut/b0orohWnEB0BsS+/qWP178vzO6zBu55ScQmRjvVmUkv+EKpyf+fprRlixiGd/i+Q/NwLSo+gH1K47eq2TSDT/JQOP5vs+gVwiwY8tykL7QxIeR4fDxYoXlAyk0sIi2SC0B9EnVWhJbCmBtmqT9Ay/YEx8PS917tuB0CqZIwoLMkLWLxOw=";
    public String generateToken(String username) {
        Map<String , Object> claims=new HashMap<>();
        return createToken(claims,username);
    }

    private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*60*24))
                .signWith(secretKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key secretKey() {
        byte[] keys= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keys);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims,T> claimResolver) {
        final Claims claims=extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isValidToken(String token, UserDetails userDetails) {
        final String username=extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }
}
