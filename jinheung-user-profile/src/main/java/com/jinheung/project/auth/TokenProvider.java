package com.jinheung.project.auth;

import com.jinheung.common.dto.auth.ParsedUserDataByJwtToken;
import com.jinheung.project.domain.user.entity.Authority;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider implements InitializingBean {

    private static final String AUTHORITIES_KEY = "Authorities";
    private static final String USER_ROLE_NAME = "user_role_name";
    private static final String USER_ROLE_VALUE = "user_role_value";

    @Value("${token.access-token-secret}")
    private String secret;

    @Value("${token.access-token-expired}")
    private Long accessTokenExpiration;

    private Key key;

    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);

    }
    //
    public String createJwtAccessTokenByUser(Long id, Collection<Authority> authorityList) {

        String authorities = authorityList.stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));

        Date validity =  new Date(new Date().getTime() + accessTokenExpiration * 1000);
        return Jwts.builder()
            .setSubject(id.toString())
            .claim(AUTHORITIES_KEY, authorities)
            .signWith(key, SignatureAlgorithm.HS512)
            .setExpiration(validity)
            .compact();
    }

    public ParsedUserDataByJwtToken getUserIdAndAuthorityByJwtAccessToken(String token) {
        try {
            Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

            Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            return new ParsedUserDataByJwtToken(Long.valueOf(claims.getSubject()), authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()), claims.getExpiration());
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.warn("잘못된 JWT 서명입니다.");
        } catch (UnsupportedJwtException e) {
            log.warn("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.warn("JWT 토큰이 잘못되었습니다.");
        } catch (ExpiredJwtException e) {
            log.warn("JWT 토큰이 만료.");
        }
        return null;
    }


}
