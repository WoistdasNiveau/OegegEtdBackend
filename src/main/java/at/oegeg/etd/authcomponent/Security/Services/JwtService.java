package at.oegeg.etd.authcomponent.Security.Services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static at.oegeg.etd.sharedcomponent.Constants.Constants.EXPIRATIONDATE;
import static at.oegeg.etd.sharedcomponent.Constants.Constants.GETSIGNINGKEY;

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

    public String GenerateToken(UserDetails userDetails)
    {
        return GenerateToken(new HashMap<>(),userDetails);
    }

    public String GenerateToken(Map<String, Object> extraClaims, UserDetails userDetails)
    {
        return "Bearer "+ Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .claim("roles", userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(EXPIRATIONDATE)
                .signWith(GETSIGNINGKEY(), SignatureAlgorithm.HS256)
                .compact();
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
