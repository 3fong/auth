package com.zzlh.auth.util;

import java.math.BigDecimal;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Pattern;

/**
 * @Description 工具类
 * @author liulei
 * @date 2018年10月15日 上午9:24:56
 */
public class AssitUtil {
	 /**
                * 是否简单密码 必须同时包含数字与大小字母
     * @param password
     * @return
     */
    public static boolean isSimple(String password) {
        Pattern pattern = Pattern.compile("(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])[a-zA-Z0-9]*");
        return !pattern.matcher(password).find();
    }

    /**
                *  转换
     * @param date
     * @return
     */
    public static Date convertDate(BigDecimal date){
        if(date!=null){
            try {
                return new SimpleDateFormat("yyyyMMddhhmmss").parse(String.valueOf(date));
            } catch (ParseException e) {
                return new Date();
            }
        }
        return new Date();
    }

    /**
               * 计算相差多少天
     * @param start
     * @param end
     * @return
     */
    public static int getDatePoor(Date start, Date end) {
        long nd = 1000 * 24 * 60 * 60;
        // long ns = 1000;
        // 获得两个时间的毫秒时间差异
        long diff = start.getTime() - end.getTime();
        // 计算差多少天
        long day = diff / nd;
        return (int) day;
    }
}
