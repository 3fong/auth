package com.zzlh.auth.credential;

import org.apereo.cas.authentication.UsernamePasswordCredential;

/**
 * CA 用户凭证信息对象 增加CA使用的类型和随机数
 *
 * Created by Sofar on 2016-04-08.
 */
public class CaCredential extends UsernamePasswordCredential {

    /** Unique ID for serialization. */
    private static final long serialVersionUID = -700605081472810939L;

    private String type;

    private String random;

    /** Default constructor. */
    public CaCredential() {}

    /**
     * Creates a new instance with the given username and password.
     *
     * @param userName Non-null user name.
     * @param password Non-null password.
     */
    public CaCredential(final String userName, final String password) {
        super(userName,password);
    }

    public CaCredential(String username, String password, String random) {
        super(username,password);
        this.random = random;
    }

    public CaCredential(String username, String password, String type, String random) {
        super(username,password);
        this.type = type;
        this.random = random;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getRandom() {
        return random;
    }

    public void setRandom(String random) {
        this.random = random;
    }


}
