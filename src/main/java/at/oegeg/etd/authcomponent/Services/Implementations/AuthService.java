package at.oegeg.etd.authcomponent.Services.Implementations;

import at.oegeg.etd.authcomponent.DataTransferObjects.Request.AuthenticationRequest;
import at.oegeg.etd.authcomponent.DataTransferObjects.Response.AuthenticationResponse;
import at.oegeg.etd.authcomponent.Security.Services.JwtService;
import at.oegeg.etd.authcomponent.Services.Interfaces.IAuthService;
import at.oegeg.etd.sharedcomponent.DataTransferObjects.Request.UserRequest;
import at.oegeg.etd.sharedcomponent.DataTransferObjects.Response.UserResponse;
import at.oegeg.etd.sharedcomponent.Entities.Enums.Role;
import at.oegeg.etd.sharedcomponent.Entities.TokenBlackList;
import at.oegeg.etd.sharedcomponent.Entities.UserEntity;
import at.oegeg.etd.sharedcomponent.Repository.ITokenBlackListRepository;
import at.oegeg.etd.sharedcomponent.Repository.IUserEntityRepository;
import io.leangen.graphql.annotations.GraphQLArgument;
import io.leangen.graphql.annotations.GraphQLMutation;
import io.leangen.graphql.annotations.GraphQLQuery;
import io.leangen.graphql.annotations.GraphQLRootContext;
import io.leangen.graphql.spqr.spring.annotations.GraphQLApi;
import io.leangen.graphql.spqr.spring.autoconfigure.DefaultGlobalContext;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.ArrayList;
import java.util.List;

import static at.oegeg.etd.sharedcomponent.Constants.Constants.AUTHORIZATIONHEADER;


@Service
@RequiredArgsConstructor
@GraphQLApi
public class AuthService implements IAuthService
{
    // == fields ==
    private final IUserEntityRepository _userRepository;
    private final PasswordEncoder _passwordEncoder;
    private final AuthenticationManager _authenticationManager;
    private final JwtService _jwtService;
    private final ITokenBlackListRepository _tokenBlackListRepository;

    // == mutations ==
    @Override
    @GraphQLMutation(name = "CreateUser")
    @PreAuthorize("hasRole('ROLE_LEADER')")
    public void CreateUser(@GraphQLArgument(name = "user") UserRequest user)
    {
        UserEntity userEntity = UserRequestToEntity(user);
        userEntity.getRoles().add(Role.USER);
        _userRepository.save(userEntity);
    }

    @Override
    @GraphQLMutation(name = "SetRole")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public void SetRole(@GraphQLArgument(name = "emailOrTelefoneNumber") String emailOrTelefoneNumber, @GraphQLArgument(name = "role") Role role)
    {
        UserEntity user = _userRepository.findByEmailOrTelephoneNumber(emailOrTelefoneNumber).orElseThrow();
        user.getRoles().add(role);
        _userRepository.save(user);
    }

    @Override
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GraphQLMutation(name = "RemoveRole")
    public AuthenticationResponse RemoveRole(@GraphQLArgument(name = "emailOrTelephoneNumber") String emailOrTelephoneNumber,
                                             @GraphQLArgument(name = "role") Role role,
                                             @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env)
    {
        UserEntity user = _userRepository.findByEmailOrTelephoneNumber(emailOrTelephoneNumber).orElseThrow();
        user.getRoles().remove(role);
        _userRepository.save(user);

        InvalidateToken(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER));

        return AuthenticationResponse.builder()
                .token(_jwtService.GenerateToken(user))
                .build();
    }

    @Override
    @GraphQLMutation(name = "ChangeEmail")
    @PreAuthorize("hasRole('ROLE_USER')")
    public AuthenticationResponse ChangeEmail(@GraphQLArgument(name = "oldEmail") String oldEmail,
                            @GraphQLArgument(name = "newEmail") String newEmail,
                            @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env)
    {
        UserEntity user = _userRepository.findByEmailOrTelephoneNumber(oldEmail).orElseThrow();
        user.setEmail(newEmail);
        _userRepository.save(user);

        InvalidateToken(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7));

        String token = _jwtService.GenerateToken(user);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }
    @Override
    @GraphQLMutation(name = "ChangeTelephoneNumber")
    @PreAuthorize("hasRole('ROLE_USER')")
    public AuthenticationResponse ChangeTelephohneNumber(@GraphQLArgument(name = "oldTelephoneNumber") String oldTelephoneNumber,
                                       @GraphQLArgument(name = "newTelephoneNumber") String newTelephoneNumber,
                                       @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env)
    {
        UserEntity user = _userRepository.findByEmailOrTelephoneNumber(oldTelephoneNumber).orElseThrow();
        user.setTelephoneNumber(newTelephoneNumber);
        _userRepository.save(user);

        InvalidateToken(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7));

        String token = _jwtService.GenerateToken(user);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }

    @Override
    @GraphQLMutation(name = "ChangeName")
    @PreAuthorize("hasRole('ROLE_USER')")
    public void ChangeName(@GraphQLArgument(name = "telephoneNumberOrEmail") String telephoneNumberOrEmail, @GraphQLArgument(name = "newName") String newName)
    {
        UserEntity user = _userRepository.findByEmailOrTelephoneNumber(telephoneNumberOrEmail).orElseThrow();
        user.setName(newName);
        _userRepository.save(user);
    }

    //@Override
    @GraphQLMutation(name = "ChangePassword")
    @PreAuthorize("hasRole('ROLE_USER')")
    public AuthenticationResponse ChangePassword(@GraphQLArgument(name = "emailOrTelephoneNumber") String emailOrTelephoneNumber,
                                                 @GraphQLArgument(name = "newPassword") String newPassword,
                                                 @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env) throws Exception
    {
        String extracted = _jwtService.ExtractUsername(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7));
        if(extracted.equals(emailOrTelephoneNumber))
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumber(emailOrTelephoneNumber).orElseThrow();
            user.setPassword(_passwordEncoder.encode(newPassword));
            _userRepository.save(user);

            InvalidateToken(extracted);

            String token = _jwtService.GenerateToken(user);
            return AuthenticationResponse.builder()
                    .token(token)
                    .build();
        }
        throw new Exception("telephone Numbers or Emails do not align");
    }

    // == queries ==
    @Override
    @GraphQLQuery(name = "Authenticate")
    @PreAuthorize("hasRole('ROLE_ANONYMOUS')")
    public AuthenticationResponse Authenticate(@GraphQLArgument(name="AuthenticationRequest") AuthenticationRequest request)
    {
        _authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        UserEntity user = _userRepository.findByEmailOrTelephoneNumber(request.getEmail()).orElseThrow();
        String token = _jwtService.GenerateToken(user);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }


    // private methods ==
    @PostConstruct
    private void Initialize()
    {
        for (TokenBlackList token : _tokenBlackListRepository.findAll())
        {
            try
            {
                if (_jwtService.IsTokenExpired(token.token))
                {
                    _tokenBlackListRepository.delete(token);
                }
            }
            catch (Exception ex)
            {
                _tokenBlackListRepository.delete(token);
            }
        }
        try
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumber("oliver01@kabsi.at").orElseThrow();
        }
        catch (Exception ex)
        {
            UserEntity user = UserEntity.builder()
                    .name("Oliver Stöckl")
                    .email("oliver01@kabsi.at")
                    .password(_passwordEncoder.encode("Passwort"))
                    .roles(List.of(Role.valueOf(Role.ADMIN.name())))
                    .build();
            _userRepository.save(user);
        }

    }

    private void InvalidateToken(String token)
    {
        TokenBlackList blacklisted = TokenBlackList.builder()
                .token(token)
                .build();
        _tokenBlackListRepository.save(blacklisted);
    }

    private UserResponse UserEntityToResponse(UserEntity user)
    {
        return UserResponse.builder()
                .name(user.getName())
                .email(user.getEmail())
                .telephoneNumber(user.getTelephoneNumber())
                .responsibleFor(user.getResponsibleFor())
                .createdWorks(user.getCreatedWorks())
                .createdVehicles(user.getCreatedVehicles())
                .build();
    }
    private UserEntity UserRequestToEntity(UserRequest user)
    {
        return UserEntity.builder()
                .name(user.getName())
                .email(user.getEmail())
                .telephoneNumber(user.getTelephoneNumber())
                .responsibleFor(user.getResponsibleFor())
                .createdWorks(user.getCreatedWorks())
                .createdVehicles(user.getCreatedVehicles())
                .password(_passwordEncoder.encode(user.getPassword()))
                .roles(new ArrayList<>())
                .build();
    }
}
