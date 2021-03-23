package com.example.gateway.Mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface RoleMapper {
    @Select("select roles from role where url=#{url}")
    String getRole(String url);
}