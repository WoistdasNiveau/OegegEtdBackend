package at.oegeg.etd.authcomponent.Security.Services;

import at.oegeg.etd.sharedcomponent.Entities.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static at.oegeg.etd.sharedcomponent.Constants.Constants.GETSIGNINGKEY;

@ComponentScan(basePackages = "at.oegeg.etd.sharedcomponent.Constants")
@Service
public class JwtService
{
    public String ExtractUsername(String token)
    {
        return ExtractClaim(token, Claims::getSubject);
    }

    public <T> T ExtractClaim(String token, Function<Claims,T> ClaimsResolver)
    {
        final Claims claims = ExtractAllClaims(token);
        return ClaimsResolver.apply(claims);
    }

    public String GenerateToken(UserEntity userDetails)
    {
        return GenerateToken(new HashMap<>(),userDetails);
    }

    public String GenerateToken(Map<String, Object> extraClaims, UserEntity userDetails)
    {
        //JwtBuilder jwt = Jwts.builder()
        //        .setClaims(extraClaims)
        //        .setSubject(userDetails.getUsername())
        //        .setIssuedAt(new Date(System.currentTimeMillis()))
        //        .setExpiration(new Date(System.currentTimeMillis()+1000*60*60))
        //        .signWith(GETSIGNINGKEY(), SignatureAlgorithm.HS256);
//
        //for(GrantedAuthority role : userDetails.getAuthorities())
        //{
        //    jwt.claim("Role",role);
        //}
        //String token = "Bearer " + jwt.compact();

        String token = "Bearer "+ Jwts
                    .builder()
                    .setClaims(extraClaims)
                    .setSubject(userDetails.getUsername())
                    .claim("Role", userDetails.getRole())
                    //.claim("Role", userDetails.getAuthorities())
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis()+1000*60*60))
                    .signWith(GETSIGNINGKEY(), SignatureAlgorithm.HS256)
                    .compact();

        return token;
    }

    public boolean IsTokenValid(String token, UserDetails userDetails)
    {
        final String emailOrTelefoneNumber = ExtractUsername(token);
        return (emailOrTelefoneNumber.equals(userDetails.getUsername()) && !IsTokenExpired(token));
    }

    public boolean IsTokenExpired(String token)
    {
        return ExtractExpiration(token).before(new Date(System.currentTimeMillis()));
    }

    // == private methods ==
    private Claims ExtractAllClaims(String token)
    {
        return Jwts
                .parserBuilder()
                .setSigningKey(GETSIGNINGKEY())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Date ExtractExpiration(String token)
    {
        return ExtractClaim(token, Claims::getExpiration);
    }
}
