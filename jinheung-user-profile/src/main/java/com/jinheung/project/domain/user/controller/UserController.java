package com.jinheung.project.domain.user.controller;


import com.jinheung.common.dto.auth.ParsedUserDataByJwtToken;
import com.jinheung.project.auth.TokenProvider;
import com.jinheung.project.domain.user.entity.Authority;
import com.jinheung.project.domain.user.entity.User;
import com.jinheung.project.domain.user.service.UserService;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;


import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@RestController
@RequestMapping
@Slf4j
public class UserController {

    private final TokenProvider tokenProvider;
    private final UserService userService;

    @GetMapping("/user/token/verify")
    @ApiOperation("유저 롤 가져오기")
    public ResponseEntity<ParsedUserDataByJwtToken> getUserAuthority(
        @RequestHeader(name = HttpHeaders.AUTHORIZATION) String bearerToken
    ) {

        if(bearerToken == null || bearerToken.isEmpty()) {
            return ResponseEntity.ok(null);
        }

        if (!StringUtils.hasText(bearerToken) || !bearerToken.startsWith("Bearer ")) {
            return ResponseEntity.ok(null);
        }

        bearerToken = bearerToken.substring(7);

        ParsedUserDataByJwtToken parsedUserDataByJwtToken
            = tokenProvider.getUserIdAndAuthorityByJwtAccessToken(bearerToken);
        return ResponseEntity.ok(parsedUserDataByJwtToken);
    }

    @GetMapping("/user/token/test/{id}")
    public ResponseEntity<String> testTokenProvider(
        @PathVariable(name = "id") Long id
    ) {
        String token = tokenProvider.createJwtAccessTokenByUser(id, new ArrayList<>() {{
            add(new Authority("ROLE_USER"));
        }});
        return ResponseEntity.ok(token);
    }

    @GetMapping("/user/token/{id}")
    public ResponseEntity<String> getTokenById(
        @PathVariable(name = "id") Long id
    ) {
        User user = userService.findByUserId(id);
        String token = tokenProvider.createJwtAccessTokenByUser(
            user.getId(),
            user.getAuthorities());
        return ResponseEntity.ok(token);
    }
}
