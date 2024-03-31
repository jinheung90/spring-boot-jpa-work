package com.jinheung.project.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jinheung.common.consts.AuthHeaderNames;
import com.jinheung.project.auth.redis.service.RefreshTokenService;
import com.jinheung.project.clients.UserResourceService;
import com.jinheung.project.config.RedisConfig;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;
import com.jinheung.common.dto.auth.ParsedUserDataByJwtToken;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Component
@Slf4j
public class AuthFilterFactory extends AbstractGatewayFilterFactory<AuthFilterFactory.Config> {


    private RefreshTokenService refreshTokenService;
    private UserResourceService userResourceService;
    private static final String REFRESH_REDIS_KEY = "refresh-redis-key";
    private static final String REFRESH_TOKEN_HEADER_NAME = "refresh-token";

    public AuthFilterFactory(
        RefreshTokenService refreshTokenService,
        UserResourceService userResourceService) {
        super(Config.class);
        this.refreshTokenService = refreshTokenService;
        this.userResourceService = userResourceService;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            final ServerHttpRequest request = exchange.getRequest();

            final HttpHeaders headers = request.getHeaders();
            final List<String> headerVal = headers.get(HttpHeaders.AUTHORIZATION);
            final String token = resolveToken(headerVal);
            userResourceService.verifyToken(token).map(res -> {
                if (res != null && res.getUserId() != null && !res.getUserId().equals(0L)) {
                    final String userId = res.getUserId().toString();
                    final String[] authorities = res.getAuthorities().toArray(String[]::new);
                    request.mutate().header(AuthHeaderNames.ACCESS_TOKEN_HEADER, token).build();
                    request.mutate().header(AuthHeaderNames.USER_ID, userId).build();
                    request.mutate().header(AuthHeaderNames.USER_AUTHORITIES,
                        authorities).build();
                }
                return null;
            });

            return chain.filter(exchange.mutate().request(request).build());
//            } else {
//                List<String> refreshHeaderVal = headers.get(REFRESH_TOKEN_HEADER_NAME);
//                if (refreshHeaderVal == null || refreshHeaderVal.isEmpty()) {
//                    return chain.filter(exchange.mutate().request(request).build());
//                }
//                Mono<String> newRefreshToken = checkRefresh(refreshHeaderVal);

//            }
//            return chain.filter(exchange);

        };
    }

    @Getter
    public static class Config {

    }

    private String resolveToken(List<String> headerVal) {

        if(headerVal == null || headerVal.isEmpty()) {
            return null;
        }

        String strToken = headerVal.get(0);
        if (StringUtils.hasText(strToken) && strToken.startsWith("Bearer ")) {
            return strToken.substring(7);
        }

        return null;
    }


}
