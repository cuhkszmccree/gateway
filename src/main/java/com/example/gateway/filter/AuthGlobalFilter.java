package com.example.gateway.filter;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.example.gateway.Constant.CommonResult;
import com.example.gateway.component.RestAuthenticationEntryPoint;
import com.nimbusds.jose.JWSObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.Charset;
import java.text.ParseException;

@Component
public class AuthGlobalFilter implements GlobalFilter, Ordered {

    @Autowired
    RedisTemplate redisTemplate;
    @Autowired
    RestAuthenticationEntryPoint restAuthenticationEntryPoint;


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//        System.out.println("getin");
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
//        System.out.println("token " + token);
        if (StrUtil.isEmpty(token)) {
//            System.out.println(12345);
            return chain.filter(exchange);
        }
        try {
            //从token中解析用户信息
            String realToken = token.replace("Bearer ", "");
            JWSObject jwsObject = JWSObject.parse(realToken);
//            System.out.println("jwsObject" + jwsObject);
            String userStr = jwsObject.getPayload().toString();
//            System.out.println("userStr" + userStr);
            //获取token唯一标识jti
            JSONObject jsonObject = JSONUtil.parseObj(userStr);
            String jti = jsonObject.getStr("jti");
            //检查token是否在黑名单中
            Boolean isLogout = redisTemplate.hasKey(jti);
            if(isLogout){
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.OK);
                response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
                String body = JSONUtil.toJsonStr(CommonResult.unauthorized("JWT has already expired"));
                DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(Charset.forName("UTF-8")));
                return response.writeWith(Mono.just(buffer));
            }
            //将用户信息写入Http Header
            ServerHttpRequest request = exchange.getRequest().mutate().header("user", userStr).build();
            exchange = exchange.mutate().request(request).build();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
