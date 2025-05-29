package ao.samid.auth.service;


// Burada tokeni yoxlayib, useri set edirik
// Eger token dogrudursa, useri set edirik
// Eger token sehvdirse, 401 statusu qaytaririq
// Eger token vaxti bitmisse, 401 statusu qaytaririq
// Eger token revoked olubsa, 401 statusu qaytaririq

import ao.samid.auth.entity.Role;
import ao.samid.auth.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtTokenService {

    @Value("${security.jwt.secret-key.access-key}")
    private String accessSecretKey;
    @Value("${security.jwt.secret-key.refresh-key}")
    private String refreshSecretKey;
    @Value("${security.jwt.access-token-expiration}")
    private long accessTokenExpire;
    @Value("${security.jwt.refresh-token-expiration}")
    private long refreshTokenExpire;

    public String generateAccessToken(User user) {
        List<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        return Jwts.builder()
                .subject(user.getUsername())// jwt tokene subject olaraq usernamei set edirik
                .claim("roles", roles)
                .claim("time", System.currentTimeMillis()) //eslinde bu altdaki eynidi prosta 1solDev bele edib
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpire))// expiration date-i generate edirem
                .signWith(getSigninKey(accessSecretKey))// tokeni generate edende zaman bizim access keyi istifade edir
                .compact(); // tokeni generate edirem
    }

    public String generateRefreshToken(User user) {
        return Jwts.builder()
                .claim("time", System.currentTimeMillis())
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExpire))
                .signWith(getSigninKey(refreshSecretKey))
                .compact();
    }

    public boolean isValidAccessToken(String token) {
//        String tokenUsername = getUsernameFromToken(token, accessSecretKey);
        return isTokenExpired(token, accessSecretKey);
    }

    public boolean isValidRefreshToken(String token) {
        //String tokenUsername = getUsernameFromToken(token, refreshSecretKey);
        return isTokenExpired(token, refreshSecretKey);
    }
    public String getUsernameFromAccessToken(String token) {
        return getUsernameFromToken(token, accessSecretKey);
    }

    public String getUsernameFromRefreshToken(String token) {
        return getUsernameFromToken(token, refreshSecretKey);
    }

    private String getUsernameFromToken(String token, String key) {
        // biz bura keyi ona gore veririk ki o secret ve ya access keyi bilmese token username-i cixarda bilmesin
        return extractClaim(token, Claims::getSubject, key);
    }
/*
* Commente alinmis hisseler tokenin bazada saxlandigi keys ucundur
* */
//    public Token getToken(String token) {
//        return tokenRepository.findByToken(token)
//                .orElseThrow(() -> new CustomException("Token not find", 401, HttpStatus.UNAUTHORIZED));
//    }

    private boolean isTokenExpired(String token, String key) {
        return !extractExpiration(token,key).before(new Date());
//        try{
//            return !extractExpiration(token,key).before(new Date());
//        } catch (ExpiredJwtException exception) {
//            Optional<Token> byToken = tokenRepository.findByToken(token);
//            if(byToken.isPresent()){
//                Token token1= byToken.get();
//                token1.setExpired(true);
//                token1.setRevoked(true);
//                tokenRepository.save(token1);
//            }
//            throw exception;
//        }
    }

    private Date extractExpiration(String token, String key) {
        Date date = extractClaim(token, Claims::getExpiration, key);
        System.out.println(date);
        return date;
    }

    private <T> T extractClaim(String token, Function<Claims, T> resolver, String key) {
        Claims claims = extractAllClaims(token, key);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token, String key) {
        return Jwts
                .parser()
                .verifyWith(getSigninKey(key))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
//
    private SecretKey getSigninKey(String key) {
        String base64UrlKey = key.replace('+', '-').replace('/', '_');
        byte[] keyBytes = Decoders.BASE64URL.decode(base64UrlKey);
        return Keys.hmacShaKeyFor(keyBytes);

    }

}
