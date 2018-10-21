package com.zzlh.auth.handler;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;

import org.apereo.cas.authentication.exceptions.InvalidLoginTimeException;
import org.apereo.inspektr.common.web.ClientInfoHolder;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

/**
 * 密码重复错误
 * Created by xieyuan on 2017/9/19.
 */
public class PasswordRetryHandlerInterceptor{
    private Integer time=15;

    private LoadingCache<String, Integer> cache= CacheBuilder.newBuilder().expireAfterAccess(time, TimeUnit.MINUTES).build(new CacheLoader<String, Integer>() {
        public Integer load(String key) throws Exception {
            return 0;
        }
    });

    public void vaildTime(HttpServletRequest request) throws InvalidLoginTimeException {
        try {
            if(cache.get(constructKey(request))>5){
                throw new InvalidLoginTimeException();
            }
        } catch (ExecutionException e) {
            throw new InvalidLoginTimeException(e.getMessage());
        }
    }

    public void countTime(HttpServletRequest request) throws InvalidLoginTimeException{
        try {
            cache.put(constructKey(request),cache.get(constructKey(request))+1);
        } catch (ExecutionException e) {
            throw new InvalidLoginTimeException(e.getMessage());
        }
    }

    private String constructKey(final HttpServletRequest request) {
        final String username = request.getParameter("username");

        if (username == null) {
            return request.getRemoteAddr();
        }
        return ClientInfoHolder.getClientInfo().getClientIpAddress() + ';' + username.toLowerCase();
    }

    public Integer getTime() {
        return time;
    }

    public void setTime(Integer time) {
        this.time = time;
    }
}
