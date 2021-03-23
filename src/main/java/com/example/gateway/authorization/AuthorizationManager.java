package com.example.gateway.authorization;

import cn.hutool.core.convert.Convert;
import com.example.gateway.Constant.AuthConstant;
import com.example.gateway.Mapper.RoleMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 鉴权管理器，用于判断是否有资源的访问权限
 */
@Component
public class AuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {
    @Autowired
    private RoleMapper roleMapper;

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> mono, AuthorizationContext authorizationContext) {
        ServerHttpRequest request = authorizationContext.getExchange().getRequest();
        //对应跨域的预检请求直接放行
        if(request.getMethod()== HttpMethod.OPTIONS){
            return Mono.just(new AuthorizationDecision(true));
        }
        //从Mysql Role表中获取当前路径可访问角色列表
        URI uri = request.getURI();
        String path = uri.getPath();
        String roles = roleMapper.getRole(path);
        //System.out.println(roles);
        List<String> role_list = new ArrayList<>();
        for(String s:roles.split(",")){
            role_list.add(s);
        }
        List<String> authorities = role_list.stream().map(i -> i = AuthConstant.AUTHORITY_PREFIX + i).collect(Collectors.toList());

        //认证通过且角色匹配的用户可访问当前路径
        return mono
                .filter(Authentication::isAuthenticated)
                .flatMapIterable(Authentication::getAuthorities)
                .map(GrantedAuthority::getAuthority)
                .any(authorities::contains)
                .map(AuthorizationDecision::new)
                .defaultIfEmpty(new AuthorizationDecision(false));
    }

}
