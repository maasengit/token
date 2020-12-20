package com.abc.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.impl.DefaultClaims;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class TokenUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenUtil.class);

    // 签名算法
    private static final SignatureAlgorithm ALGORITHM = SignatureAlgorithm.HS512;
    // 刷新时刻属性
    private static final String REFRESH_AT = "rat";
    // 签发人
    private static final String issuer = "com.abc";
    // 签名密钥
    private static final String secret = "kDQ@3qtrYokz%O9v";

    // 读取黑名单
    private static final List<String> blackList = new ArrayList<>();
    static {
        try {
            List lines = IOUtils.readLines(Thread.currentThread().getContextClassLoader().
                    getResourceAsStream("blacklist_token"), "utf-8");
            blackList.addAll(lines);
        } catch (IOException e) {
            LOGGER.warn("Failed to read black list for token", e);
        }
    }

    /**
     * 生成普通token。
     *
     * @param audience 用户id或应用id
     * @param subject 业务相关内容
     * @param expiration 过期时间，单位：秒
     *
     * @return 普通Token
     */
    public static String generateToken(String audience, String subject, Integer expiration) {
        Date issuedAt = new Date();
        return Jwts.builder()
                .signWith(ALGORITHM, secret)
                .setExpiration(DateUtils.addSeconds(issuedAt, expiration))
                .setIssuedAt(issuedAt)
                .setIssuer(issuer)
                .setAudience(audience)
                .setSubject(subject)
                .compact();
    }

    /**
     * 解析token得到Audience。
     * 支持普通Token和会话Token
     *
     * @param token
     * @return audience
     *
     * @throws TokenInvalidException Token无效
     * @throws TokenExpiredException Token过期
     */
    public static String getAudienceFromToken(String token) {
        try {
            return getClaimsFromToken(token).getAudience();
        } catch (SignatureException e) {
            throw new TokenInvalidException(token);
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException(token);
        } catch (Exception e) {
            throw new TokenInvalidException(token);
        }
    }

    /**
     * 解析token得到Subject。
     *
     * 支持普通Token和会话Token
     *
     * @param token
     * @return subject
     *
     * @throws TokenInvalidException Token无效
     * @throws TokenExpiredException Token过期
     */
    public static String getSubjectFromToken(String token) {
        try {
            return getClaimsFromToken(token).getSubject();
        } catch (SignatureException e) {
            throw new TokenInvalidException(token);
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException(token);
        } catch (Exception e) {
            throw new TokenInvalidException(token);
        }
    }

    /**
     * 验证token是否有效
     *
     * @param token 普通Token
     *
     * @throws TokenInvalidException Token无效
     * @throws TokenExpiredException Token过期
     */
    public static void checkToken(String token) {
        String audience;
        try {
            audience = getClaimsFromToken(token).getAudience();
        } catch (SignatureException e) {
            throw new TokenInvalidException(token);
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException(token);
        } catch (Exception e) {
            throw new TokenInvalidException(token);
        }

        if (blackList.contains(audience)) {
            throw new TokenBlacklistException(token);
        }
    }

    public static Claims getClaimsFromToken(String token) throws SignatureException, ExpiredJwtException {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 生成会话Token，同时设置刷新时刻
     *
     * @param audience 用户id或应用id
     * @param subject 业务相关内容
     * @param expiration 过期时间，单位：秒
     *
     * @return 会话Token
     */
    public static String generateSessionToken(String audience, String subject, Integer expiration) {
        Date issuedAt = new Date();
        Claims claims = new DefaultClaims();
        setDate(claims, REFRESH_AT, issuedAt);
        return Jwts.builder()
                .setClaims(claims)
                .signWith(ALGORITHM, secret)
                .setExpiration(DateUtils.addSeconds(issuedAt, expiration))
                .setIssuedAt(issuedAt)
                .setIssuer(issuer)
                .setAudience(audience)
                .setSubject(subject)
                .compact();
    }

    /**
     * 检查会话Token，超过最短刷新时间或最长刷新时间，抛出过期异常；否则：抛出刷新异常，调用方需要刷新Token
     * @param token 会话Token
     * @param leastRefreshTime 二级过期时间
     * @param mostRefreshTime 三级过期时间
     *
     * @throws TokenInvalidException Token无效
     * @throws TokenExpiredException Token过期
     * @throws TokenRefreshException Token需要刷新
     */
    public static void checkSessionToken(String token, Integer leastRefreshTime, Integer mostRefreshTime) {
        String audience;
        try {
            audience = getClaimsFromToken(token).getAudience();
        } catch (ExpiredJwtException e) {
            Claims claims = e.getClaims();
            Date now = new Date();
            // 签发时间
            Date issueAt = claims.getIssuedAt();
            // 上次刷新时间
            Object refreshAtObj = claims.get(REFRESH_AT);
            Date refreshAt = null;
            if (refreshAtObj != null) {
                refreshAt = getDate(refreshAtObj);
            }

            // 超过三级过期时间
            if (DateUtils.addSeconds(issueAt, mostRefreshTime).before(now)) {
                throw new TokenExpiredException(token);
            }
            // 超过二级过期时间
            if (refreshAt != null && DateUtils.addSeconds(refreshAt, leastRefreshTime).before(now)) {
                throw new TokenExpiredException(token);
            }
            throw new TokenRefreshException(token);
        } catch (Exception e) {
            throw new TokenInvalidException(token);
        }
        if (blackList.contains(audience)) {
            throw new TokenBlacklistException(token);
        }
    }

    /**
     * 刷新会话Token, 更新一级过期时间和刷新时刻。
     *
     * @param token 老会话令牌
     * @param expirationTime 令牌的一级过期时间
     * @param leastRefreshTime 令牌的二级过期时间
     * @param mostRefreshTime 令牌的三级过期时间
     * @return
     */
    public static String refreshSessionToken(String token, Integer expirationTime, Integer leastRefreshTime,
                                      Integer mostRefreshTime) {
        Date now = new Date();
        Claims claims;
        try {
            claims = getClaimsFromToken(token);
        } catch (ExpiredJwtException e) {
            claims = e.getClaims();
            Date issueAt = claims.getIssuedAt();
            Object refreshAtObj = claims.get(REFRESH_AT);
            Date refreshAt = null;
            if (refreshAtObj != null) {
                refreshAt = getDate(refreshAtObj);
            }
            // 超过最长刷新时间
            if (DateUtils.addSeconds(issueAt, mostRefreshTime).before(now)) {
                throw new TokenExpiredException(token);
            }
            // 超过最短刷新时间
            if (refreshAt != null && DateUtils.addSeconds(refreshAt, leastRefreshTime).before(now)) {
                throw new TokenExpiredException(token);
            }
            claims = e.getClaims();
        } catch (Exception e) {
            // 非法Token
            throw new TokenInvalidException(token);
        }

        // 更新刷新时刻
        setDate(claims, REFRESH_AT, now);
        return Jwts.builder()
                .setClaims(claims)
                .signWith(ALGORITHM, secret)
                .setExpiration(DateUtils.addSeconds(now, expirationTime))
                .compact();
    }

    private static void setDate(Claims claims, String name, Date d) {
        if (d == null) {
            claims.remove(name);
        } else {
            long seconds = d.getTime() / 1000;
            claims.put(name, seconds);
        }
    }

    private static Date getDate(Object v) {
        long seconds = ((Number) v).longValue();
        long millis = seconds * 1000;
        return new Date(millis);
    }
}
