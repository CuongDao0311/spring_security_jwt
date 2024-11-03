package com.cuongdao.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "8380b9a2ffc68f615c939b09b12a55e4c301e14ffde201b508d07298ab40436ae9ccf7de90918cd081f89a6e58b8f9c2cc3510eb88b2c54faf23d48cd64037941acafe5da09177fc9dbcfb5ec849b9354d46269201b75cb8bcebbe3fd33248fd07cd1023d5647089e8d6c313c5e2b1c82a75d583deacd5cda81c06dcf90440637d161a7d49e3a3f84534109cf7bce2e02ea3a4711723f339417fd73d0fbadbbb6bef2037744c44c187b651b677ae090a8ced20ac4fd0f45a92bdc40cdd6b218cf894fa6c719800a915ef1b7b51c00cd17c5e50de85d4d8c8c265515fd829eac88e54c3a23beeacf901a6691973645760355a052a18385ec40deec0855540741c";

    public String extractUserName(String token) {
        return extractClaim(token,Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(Map<String, Objects> extraClaim, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaim)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*24))
                .signWith(getSignInkey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken (UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return userName.equals(userDetails.getUsername()) || !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInkey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInkey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
