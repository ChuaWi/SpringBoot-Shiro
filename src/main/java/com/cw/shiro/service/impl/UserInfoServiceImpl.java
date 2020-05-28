package com.cw.shiro.service.impl;


import com.cw.shiro.dao.UserInfoDao;
import com.cw.shiro.entity.UserInfo;
import com.cw.shiro.service.UserInfoService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class UserInfoServiceImpl implements UserInfoService {
    @Resource
    private UserInfoDao userInfoDao;
    @Override
    public UserInfo findByUsername(String username) {
        System.out.println("UserInfoServiceImpl.findByUsername()");
        return userInfoDao.findByUsername(username);
    }
}