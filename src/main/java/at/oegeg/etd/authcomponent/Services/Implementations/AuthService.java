package at.oegeg.etd.authcomponent.Services.Implementations;

import at.oegeg.etd.authcomponent.DataTransferObjects.Request.AuthenticationRequest;
import at.oegeg.etd.authcomponent.DataTransferObjects.Request.FirstLoginRequest;
import at.oegeg.etd.authcomponent.DataTransferObjects.Response.AuthenticationResponse;
import at.oegeg.etd.authcomponent.DataTransferObjects.Response.FirstLoginResponse;
import at.oegeg.etd.authcomponent.Security.Services.JwtService;
import at.oegeg.etd.authcomponent.Services.Interfaces.IAuthService;
import at.oegeg.etd.sharedcomponent.DataTransferObjects.Request.UserRequest;
import at.oegeg.etd.sharedcomponent.DataTransferObjects.Request.WorkRequest;
import at.oegeg.etd.sharedcomponent.DataTransferObjects.Response.UserResponse;
import at.oegeg.etd.sharedcomponent.DataTransferObjects.Response.VehicleResponse;
import at.oegeg.etd.sharedcomponent.DataTransferObjects.Response.WorkResponse;
import at.oegeg.etd.sharedcomponent.Entities.Enums.Role;
import at.oegeg.etd.sharedcomponent.Entities.TokenBlackList;
import at.oegeg.etd.sharedcomponent.Entities.UserEntity;
import at.oegeg.etd.sharedcomponent.Entities.VehicleEntity;
import at.oegeg.etd.sharedcomponent.Entities.WorkEntity;
import at.oegeg.etd.sharedcomponent.Repository.ITokenBlackListRepository;
import at.oegeg.etd.sharedcomponent.Repository.IUserEntityRepository;
import at.oegeg.etd.sharedcomponent.Repository.IVehicleRepository;
import at.oegeg.etd.sharedcomponent.Repository.IWorkRepository;
import io.leangen.graphql.annotations.GraphQLArgument;
import io.leangen.graphql.annotations.GraphQLMutation;
import io.leangen.graphql.annotations.GraphQLQuery;
import io.leangen.graphql.annotations.GraphQLRootContext;
import io.leangen.graphql.spqr.spring.annotations.GraphQLApi;
import io.leangen.graphql.spqr.spring.autoconfigure.DefaultGlobalContext;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

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
    private final IVehicleRepository _vehicleRepository;
    private final IWorkRepository _workRepository;
    private final EmailSenderService _emailSenderService;

    // == mutations ==
        @Override
        @GraphQLMutation(name = "CreateUser")
        @PreAuthorize("hasRole('ROLE_LEADER')")
        public void CreateUser(@GraphQLArgument(name = "user") UserRequest user)
        {
            String pw = RandomStringUtils.random(15, true, false);
            user.setPassword(pw);

            UserEntity userEntity = UserRequestToEntity(user);
            userEntity.setFirstLoginToken(pw);
            userEntity.getRoles().add(Role.USER);
            _userRepository.save(userEntity);

            String token = _jwtService.GenerateToken(userEntity);

            if(user.getEmail() != null || user.getEmail() != "")
            {
                _emailSenderService.SendSetPasswortMail("oliver01@kabsi.at",pw, user.getName());
            }
        }

        @Override
        @GraphQLMutation(name = "DeleteUser")
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        public void DeleteUser(@GraphQLArgument(name = "nameEmailOrTelephoneNumber") String nameEmailOrTelephoneNumber)
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(nameEmailOrTelephoneNumber).orElseThrow();
            _userRepository.delete(user);
        }

        @Override
        @GraphQLMutation(name = "SetRole")
        @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
        public AuthenticationResponse SetRole (@GraphQLArgument(name = "emailOrTelefoneNumber") String emailOrTelefoneNumber,
                                               @GraphQLArgument(name = "roles") List<Role> roles,
                                               @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env)
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(emailOrTelefoneNumber).orElseThrow();
            List<Role> userRoles = user.getRoles();
            for(Role role : roles)
            {
                if(!user.getRoles().contains(role))
                {
                    user.getRoles().add(role);
                }
            }
            Iterator<Role> iterator = user.getRoles().iterator();
            while(iterator.hasNext())
            {
                Role r = iterator.next();
                    if(!roles.contains(r))
                    {
                        iterator.remove();
                    }
            }
            _userRepository.save(user);

            if(_userRepository.findByEmailOrTelephoneNumberOrName(_jwtService.ExtractUsername(env.getNativeRequest()
                    .getHeader(AUTHORIZATIONHEADER).substring(7))).orElseThrow() == user)
            {
                return AuthenticationResponse.builder()
                        .token(_jwtService.GenerateToken(user))
                        .build();
            }
            return new AuthenticationResponse();
        }

        //@Override
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        @GraphQLMutation(name = "RemoveRole")
        public AuthenticationResponse RemoveRole (@GraphQLArgument(name = "emailOrTelephoneNumber") String
        emailOrTelephoneNumber,
                @GraphQLArgument(name = "role") Role role,
            @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env)
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(emailOrTelephoneNumber).orElseThrow();
            user.getRoles().remove(role);
            _userRepository.save(user);

            InvalidateToken(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER));

            return AuthenticationResponse.builder()
                    .token(_jwtService.GenerateToken(user))
                    .build();
        }

        //@Override
        @GraphQLMutation(name = "ChangeEmail")
        @PreAuthorize("hasRole('ROLE_USER')")
        public AuthenticationResponse ChangeEmail (@GraphQLArgument(name = "oldEmail") String oldEmail,
            @GraphQLArgument(name = "newEmail") String newEmail,
            @GraphQLRootContext DefaultGlobalContext < ServletWebRequest > env)
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(oldEmail).orElseThrow();
            user.setEmail(newEmail);
            _userRepository.save(user);
            String token;

            if(user.getEmail() == _jwtService.ExtractUsername(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7))||
                    user.getTelephoneNumber() == _jwtService.ExtractUsername(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7)))
            {
                InvalidateToken(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7));
                token = _jwtService.GenerateToken(user);
            }
            else
            {
                token = env.getNativeRequest().getHeader(AUTHORIZATIONHEADER);
            }
            return AuthenticationResponse.builder()
                    .token(token)
                    .build();
        }
        //@Override
        @GraphQLMutation(name = "ChangeTelephoneNumber")
        @PreAuthorize("hasRole('ROLE_USER')")
        public AuthenticationResponse ChangeTelephohneNumber (@GraphQLArgument(name = "oldTelephoneNumber") String oldTelephoneNumber,
                @GraphQLArgument(name = "newTelephoneNumber") String newTelephoneNumber,
            @GraphQLRootContext DefaultGlobalContext < ServletWebRequest > env)
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(oldTelephoneNumber).orElseThrow();
            user.setTelephoneNumber(newTelephoneNumber);
            _userRepository.save(user);
            String token;

            if(user.getEmail() == _jwtService.ExtractUsername(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7))||
                user.getTelephoneNumber() == _jwtService.ExtractUsername(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7)))
            {
                InvalidateToken(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7));
                token = _jwtService.GenerateToken(user);
            }
            else
            {
                token = env.getNativeRequest().getHeader(AUTHORIZATIONHEADER);
            }
            return AuthenticationResponse.builder()
                    .token(token)
                    .build();
        }

        @Override
        @GraphQLMutation(name = "ChangeName")
        @PreAuthorize("hasRole('ROLE_USER')")
        public void ChangeName (@GraphQLArgument(name = "telephoneNumberOrEmail") String
        telephoneNumberOrEmail, @GraphQLArgument(name = "newName") String newName)
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(telephoneNumberOrEmail).orElseThrow();
            user.setName(newName);
            _userRepository.save(user);
        }

        @Override
        @GraphQLMutation(name = "ChangePassword")
        @PreAuthorize("hasRole('ROLE_USER')")
        public AuthenticationResponse ChangePassword (@GraphQLArgument(name = "emailOrTelephoneNumber") String
        emailOrTelephoneNumber,
                @GraphQLArgument(name = "newPassword") String newPassword,
            @GraphQLRootContext DefaultGlobalContext < ServletWebRequest > env) throws Exception
        {
            String extracted = _jwtService.ExtractUsername(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7));
            if (extracted.equals(emailOrTelephoneNumber))
            {
                UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(emailOrTelephoneNumber).orElseThrow();
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

        @Override
        @GraphQLMutation(name = "ChangeInitialPassword")
        @PreAuthorize("hasRole('ROLE_ANONYMOUS')")
        public AuthenticationResponse ChangeInitialPassword(@GraphQLArgument(name= "token") String token,
                                                            @GraphQLArgument(name = "password") String password) throws Exception
        {
            UserEntity user = _userRepository.findByFirstLoginToken(token).orElseThrow();
            if(!user.isEnabled())
            {
                user.setPassword(_passwordEncoder.encode(password));
                user.setIsUserEnabled(true);
                user.setFirstLoginToken("");
                _userRepository.save(user);
                String newToken = _jwtService.GenerateToken(user);
                return AuthenticationResponse.builder()
                        .token(newToken)
                        .build();
            }
            throw new Exception("Could not set password");
        }

        @Override
        @GraphQLMutation(name = "SetPassword")
        @PreAuthorize("hasRole('ROLE_ANONYMOUS')")
        public FirstLoginResponse SetPassword (@GraphQLArgument(name = "firstLoginRequest") FirstLoginRequest
        firstLoginRequest)
        {
            String username = _jwtService.ExtractUsername(firstLoginRequest.getToken().substring(7));
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(username).orElseThrow();
            user.setPassword(_passwordEncoder.encode(firstLoginRequest.getPassword()));
            user.setIsUserEnabled(true);
            _userRepository.save(user);
            return FirstLoginResponse.builder()
                    .token(_jwtService.GenerateToken(user))
                    .build();
        }

        // == queries ==
        //@Override
        @GraphQLQuery(name = "Authenticate")
        @PreAuthorize("hasRole('ROLE_ANONYMOUS')")
        public AuthenticationResponse Authenticate
        (@GraphQLArgument(name = "AuthenticationRequest") AuthenticationRequest request)
        {
            _authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(request.getEmail()).orElseThrow();
            String token = _jwtService.GenerateToken(user);
            return AuthenticationResponse.builder()
                    .token(token)
                    .name(user.getName())
                    .build();
        }

        @Override
        @GraphQLQuery(name = "ValidateToken")
        @PreAuthorize("hasRole('ROLE_USER')")
        public AuthenticationResponse ValidateToken (@GraphQLRootContext DefaultGlobalContext < ServletWebRequest > env)
        {
            String username = _jwtService.ExtractUsername(env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7));
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(username).orElseThrow();
            String token = _jwtService.GenerateToken(user);
            return AuthenticationResponse.builder()
                    .token(token)
                    .name(user.getName())
                    .isEnabled(user.isEnabled())
                    .build();
        }

        @Override
        @GraphQLQuery(name = "ValidateFirstLoginToken")
        @PreAuthorize("hasRole('ROLE_ANONYMOUS')")
        public AuthenticationResponse ValidateFirstLoginToken(@GraphQLArgument(name = "token") String token) throws Exception
        {
            UserEntity user = _userRepository.findByFirstLoginToken(token).orElseThrow();
            if(!user.isEnabled())
            {
                return AuthenticationResponse.builder()
                        .isEnabled(user.isEnabled())
                        .token(token)
                        .name(user.getName())
                        .build();
            }
            throw new Exception("Token invalid");
        }

        @Override
        @GraphQLQuery(name = "ResendEmail")
        @PreAuthorize("hasRole('ROLE_LEADER')")
        public void ResendEmail(@GraphQLArgument(name = "nameEmailOrTelephoneNumber") String nameEmailOrTelephoneNumber)
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(nameEmailOrTelephoneNumber).orElseThrow();
            if(!user.isEnabled())
            {
                if(user.getEmail() != null || user.getEmail() != "")
                {
                    _emailSenderService.SendSetPasswortMail("oliver01@kabsi.at",user.getFirstLoginToken(), user.getName());
                }
            }
        }
        @Override
        @GraphQLQuery(name = "GetAllUsers")
        @PreAuthorize("hasRole('ROLE_LEADER')")
        public List<UserResponse> GetAllUsers ()
        {
            List<UserResponse> response = UserEntitiesToResponses(_userRepository.findAll());
            return response;
        }

        @Override
        @GraphQLQuery(name = "GetUser")
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        public UserResponse GetUser (@GraphQLArgument(name = "nameEmailOrTelephoneNumber") String
        nameEmailOrTelephoneNumber)
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(nameEmailOrTelephoneNumber).orElseThrow();
            UserResponse response = UserEntityToResponse(user);
            return response;
        }


        // private methods ==
        @PostConstruct
        private void Initialize ()
        {
            for (TokenBlackList token : _tokenBlackListRepository.findAll())
            {
                try
                {
                    if (_jwtService.IsTokenExpired(token.token))
                    {
                        _tokenBlackListRepository.delete(token);
                    }
                } catch (Exception ex)
                {
                    _tokenBlackListRepository.delete(token);
                }
            }
            try
            {
                UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName("oliver01@kabsi.at").orElseThrow();
            } catch (Exception ex)
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

        private void SendEmail(String message)
        {

        }

        private void InvalidateToken (String token)
        {
            TokenBlackList blacklisted = TokenBlackList.builder()
                    .token(token)
                    .build();
            _tokenBlackListRepository.save(blacklisted);
        }

        private UserResponse UserEntityToResponse (UserEntity user)
        {
            UserResponse.UserResponseBuilder builder = UserResponse.builder()
                    .name(user.getName())
                    .email(user.getEmail())
                    .telephoneNumber(user.getTelephoneNumber())
                    .responsibleFor(WorkEntityToWorkResponse(user.getResponsibleFor() != null ? user.getResponsibleFor() : new ArrayList<>()))
                    .createdWorks(WorkEntityToWorkResponse(user.getCreatedWorks() != null ? user.getCreatedWorks() : new ArrayList<>()))
                    .updatedWorks(WorkEntityToWorkResponse(user.getUpdatedWorks() != null ? user.getUpdatedWorks() : new ArrayList<>()))
                    .createdVehicles(VehicleEntitiesToVehicleResponse(user.getCreatedVehicles() != null ? user.getCreatedVehicles() : new ArrayList<>()))
                    .updatedVehicles(VehicleEntitiesToVehicleResponse(user.getUpdatedVehicles() != null ? user.getUpdatedVehicles() : new ArrayList<>()))
                    .responsibleForCount(_workRepository.countAllByResponsiblePerson(user))
                    .createdWorksCount(_workRepository.countAllByCreatedBy(user))
                    .createdVehiclesCount(_vehicleRepository.countAllByCreatedBy(user))
                    .updatedVehiclesCount(_vehicleRepository.countAllByUpdatedBy(user))
                    .updatedWorksCount(_workRepository.countAllByUpdatedBy(user))
                    .roles(user.getRoles())
                    .isEnabled(user.isEnabled());
            return builder.build();

        }
        private UserEntity UserRequestToEntity (UserRequest user)
        {
            return UserEntity.builder()
                    .name(user.getName())
                    .email(user.getEmail())
                    .telephoneNumber(user.getTelephoneNumber())
                    .responsibleFor(user.getResponsibleFor())
                    .createdWorks(user.getCreatedWorks())
                    .createdVehicles(user.getCreatedVehicles())
                    .password(_passwordEncoder.encode(user.getPassword()))
                    .roles(user.getRoles() != null ? user.getRoles() : new ArrayList<>())
                    .build();
        }

        private List<UserResponse> UserEntitiesToResponses (List < UserEntity > users)
        {
            return users.stream().map(u -> UserResponse.builder()
                    .name(u.getName())
                    .email(u.getEmail())
                    .telephoneNumber(u.getTelephoneNumber())
                    .responsibleForCount(_workRepository.countAllByResponsiblePerson(u))
                    .createdWorksCount(_workRepository.countAllByCreatedBy(u))
                    .createdVehiclesCount(_vehicleRepository.countAllByCreatedBy(u))
                    .updatedVehiclesCount(_vehicleRepository.countAllByUpdatedBy(u))
                    .updatedWorksCount(_workRepository.countAllByUpdatedBy(u))
                    .roles(u.getRoles())
                    .build()).collect(Collectors.toList());
        }

        private List<VehicleResponse> VehicleEntitiesToVehicleResponse (List < VehicleEntity > entities)
        {
            return entities.stream().map(e -> VehicleResponse.builder()
                            .identifier(e.getIdentifier())
                            .Number(e.getNumber())
                            .Type(e.getType())
                            .Status(e.getStatus())
                            .Stand(e.getStand())
                            .Priority(e.getPriority())
                            .workCount(_workRepository.countWorkEntityByVehicle(e))
                            .Works(WorkEntityToWorkResponse(e.getWorks())).build())
                    .collect(Collectors.toList());
        }

        private VehicleResponse VehicleEntityToVehicleResponse (VehicleEntity entity)
        {
            List<VehicleEntity> v = new ArrayList<>();
            v.add(entity);
            return (VehicleResponse) ((List) VehicleEntitiesToVehicleResponse(v)).stream().findFirst().orElseThrow();
        }
        private List<WorkEntity> WorkRequestToWorkEntity (List < WorkRequest > requests)
        {
            List<WorkEntity> works = new ArrayList<WorkEntity>();
            for (WorkRequest request : requests)
            {
                try
                {
                    UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(request.getResponsiblePersonEmailOrTelephoneNumber()).orElseThrow();
                    works.add(WorkEntity.builder()
                            .responsiblePerson(user)
                            .description(request.getDescription())
                            .priority(request.getPriority())
                            .identifier(UUID.randomUUID())
                            .build());
                } catch (Exception ex)
                {
                    works.add(WorkEntity.builder()
                            .description(request.getDescription())
                            .priority(request.getPriority())
                            .identifier(UUID.randomUUID())
                            .build());
                }
            }
            return works;
        }

        private List<WorkResponse> WorkEntityToWorkResponse (List < WorkEntity > entities)
        {
            List<WorkResponse> response = new ArrayList<>();
            for (WorkEntity entity : entities)
            {
                WorkResponse r = WorkResponse.builder()
                        .Description(entity.getDescription())
                        .Priority(entity.getPriority())
                        .identifier(entity.getIdentifier())
                        .build();
                if (entity.getResponsiblePerson() != null)
                    r.setResponsiblePerson(entity.getResponsiblePerson().getName());
                response.add(r);
            }
            return response;
        }
    }

