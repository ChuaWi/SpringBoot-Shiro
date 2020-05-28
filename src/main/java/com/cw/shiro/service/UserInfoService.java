package com.cw.shiro.service;

import com.cw.shiro.entity.UserInfo;

public interface UserInfoService {
    /**通过username查找用户信息;*/
    public UserInfo findByUsername(String username);
}