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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.ArrayList;
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
        @PreAuthorize("hasAnyRole('ROLE_LEADER','ROLE_ADMIN')")
        public void CreateUser(@GraphQLArgument(name = "user") UserRequest user)
        {
            user.setPassword(UUID.randomUUID().toString());
            UserEntity userEntity = UserRequestToEntity(user);

            _userRepository.save(userEntity);

            if(userEntity.getEmail() != null && !userEntity.getEmail().equals(""))
            {
                _emailSenderService.SendSetPasswortMail("oliver01@kabsi.at", userEntity.getUsername(), userEntity.getName());
            }
        }

        @Override
        @GraphQLMutation(name = "DeleteUser")
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        public void DeleteUser(@GraphQLArgument(name = "identifier") String identifier)
        {
            //UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(nameEmailOrTelephoneNumber).orElseThrow();
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();
            _userRepository.delete(user);
        }

        @Override
        @GraphQLMutation(name = "SetRole")
        @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
        public AuthenticationResponse SetRole (@GraphQLArgument(name = "identifier") String identifier,
                                               @GraphQLArgument(name = "role") Role role,
                                               @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env)
        {
            String token = ExtractToken(env);
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();
            UserEntity requestUser = _userRepository.findByIdentifier(_jwtService.ExtractUsername(token)).orElseThrow();
            //List<Role> userRoles = user.getRole();

            //for(Role role : roles)
            //{
            //    if(!user.getRole().contains(role))
            //    {
            //        user.getRole().add(role);
            //    }
            //}
            //Iterator<Role> iterator = user.getRole().iterator();
            //while(iterator.hasNext())
            //{
            //    Role r = iterator.next();
            //        if(!roles.contains(r))
            //        {
            //            iterator.remove();
            //        }
            //}
            user.setRole(role);
            _userRepository.save(user);

            if(requestUser == user)
            {
                return AuthenticationResponse.builder()
                        .token(_jwtService.GenerateToken(user))
                        .build();
            }
            return new AuthenticationResponse();
        }


        //@Override
        //@Deprecated
        //@PreAuthorize("hasRole('ROLE_ADMIN')")
        //@GraphQLMutation(name = "RemoveRole")
        //public AuthenticationResponse RemoveRole (@GraphQLArgument(name = "identifier") String identifier,
        //                                          @GraphQLArgument(name = "role") Role role,
        //                                          @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env)
        //{
        //    String token = ExtractToken(env);
        //    UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();
        //    user.getRole().remove(role);
        //    _userRepository.save(user);
//
        //    InvalidateToken(token);
//
        //    return AuthenticationResponse.builder()
        //            .token(_jwtService.GenerateToken(user))
        //            .build();
        //}

        @Override
        @GraphQLMutation(name = "ChangeEmail")
        @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_LEADER','ROLE_ADMIN')")
        public void ChangeEmail (@GraphQLArgument(name = "identifier") String identifier,
                                                   @GraphQLArgument(name = "newEmail") String newEmail,
                                                   @GraphQLRootContext DefaultGlobalContext < ServletWebRequest > env)
        {
            String token = ExtractToken(env);
            UserEntity requestuser = _userRepository.findByIdentifier(_jwtService.ExtractUsername(token)).orElseThrow();
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();
            boolean equals = requestuser.getUsername().equals(user.getUsername());

            if(requestuser.getUsername().equals(user.getUsername()) || requestuser.getRole() == Role.ADMIN)
            {
                user.setEmail(newEmail);
                _userRepository.save(user);
            }
        }
        @Override
        @GraphQLMutation(name = "ChangeTelephoneNumber")
        @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_LEADER','ROLE_ADMIN')")
        public void ChangeTelephohneNumber (@GraphQLArgument(name = "identifier") String identifier,
                                                              @GraphQLArgument(name = "newTelephoneNumber") String newTelephoneNumber,
                                                              @GraphQLRootContext DefaultGlobalContext < ServletWebRequest > env)
        {
            String token = ExtractToken(env);
            UserEntity requestuser = _userRepository.findByIdentifier(_jwtService.ExtractUsername(token)).orElseThrow();
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();

            boolean equal = (requestuser.getUsername().equals(user.getUsername()));

            if(equal || requestuser.getRole() == Role.ADMIN)
            {
                user.setTelephoneNumber(newTelephoneNumber);
                _userRepository.save(user);
            }
        }

        @Override
        @GraphQLMutation(name = "ChangeName")
        @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_LEADER','ROLE_ADMIN')")
        public void ChangeName (@GraphQLArgument(name = "identifier") String identifier,
                                @GraphQLArgument(name = "newName") String newName,
                                @GraphQLRootContext DefaultGlobalContext < ServletWebRequest > env )
        {
            String token = ExtractToken(env);
            UserEntity requestUser = _userRepository.findByIdentifier(_jwtService.ExtractUsername(token)).orElseThrow();
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();

            if(requestUser.getUsername().equals( user.getUsername()) || requestUser.getRole() == Role.ADMIN)
            {
                user.setName(newName);
                _userRepository.save(requestUser);
            }
        }

        @Override
        @GraphQLMutation(name = "ChangePassword")
        @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_LEADER','ROLE_ADMIN')")
        public AuthenticationResponse ChangePassword (@GraphQLArgument(name = "identifier") String identifier,
                                                      @GraphQLArgument(name = "newPassword") String newPassword,
                                                      @GraphQLRootContext DefaultGlobalContext < ServletWebRequest > env) throws Exception
        {
            String token = ExtractToken(env);
            UserEntity requestUser = _userRepository.findByIdentifier(_jwtService.ExtractUsername(token)).orElseThrow();
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();
            if (requestUser.getUsername().equals(user.getUsername()))
            {
                user.setPassword(_passwordEncoder.encode(newPassword));
                _userRepository.save(user);

                InvalidateToken(token);
                token = _jwtService.GenerateToken(user);
                return AuthenticationResponse.builder()
                        .token(token)
                        .build();
            }
            throw new Exception("telephone Numbers or Emails do not align");
        }

        @Override
        @GraphQLMutation(name = "ChangeInitialPassword")
        @PreAuthorize("hasRole('ROLE_ANONYMOUS')")
        public AuthenticationResponse ChangeInitialPassword(@GraphQLArgument(name= "identifier") String identifier,
                                                            @GraphQLArgument(name = "password") String password) throws Exception
        {
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();
            if(!user.isEnabled())
            {
                user.setPassword(_passwordEncoder.encode(password));
                user.setIsUserEnabled(true);
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
        public FirstLoginResponse SetPassword (@GraphQLArgument(name = "firstLoginRequest") FirstLoginRequest firstLoginRequest)
        {
            String identifier = _jwtService.ExtractUsername(firstLoginRequest.getToken().substring(7));
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();

            user.setPassword(_passwordEncoder.encode(firstLoginRequest.getPassword()));
            user.setIsUserEnabled(true);
            _userRepository.save(user);

            return FirstLoginResponse.builder()
                    .token(_jwtService.GenerateToken(user))
                    .build();
        }

        // == queries ==
        @Override
        @GraphQLQuery(name = "Authenticate")
        @PreAuthorize("hasRole('ROLE_ANONYMOUS')")
        public AuthenticationResponse Authenticate (@GraphQLArgument(name = "AuthenticationRequest") AuthenticationRequest request)
        {
            UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(request.getEmail()).orElseThrow();
            _authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getIdentifier(), request.getPassword()));

            //UserEntity user = _userRepository.findByEmailOrTelephoneNumberOrName(request.getEmail()).orElseThrow(); //must exist for this method
            String token = _jwtService.GenerateToken(user);
            return AuthenticationResponse.builder()
                    .token(token)
                    .name(user.getName())
                    .identifier(user.getIdentifier())
                    .build();
        }

        @Override
        @GraphQLQuery(name = "ValidateToken")
        @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_LEADER','ROLE_ADMIN')")
        public AuthenticationResponse ValidateToken (@GraphQLRootContext DefaultGlobalContext < ServletWebRequest > env)
        {
            String token = ExtractToken(env);
            UserEntity user = _userRepository.findByIdentifier(_jwtService.ExtractUsername(token)).orElseThrow();

            token = _jwtService.GenerateToken(user);
            return AuthenticationResponse.builder()
                    .token(token)
                    .name(user.getName())
                    .isEnabled(user.isEnabled())
                    .build();
        }

        @Override
        @GraphQLQuery(name = "ValidateFirstLoginToken")
        @PreAuthorize("hasRole('ROLE_ANONYMOUS')")
        public AuthenticationResponse ValidateFirstLoginToken(@GraphQLArgument(name = "identifier") String identifier) throws Exception
        {
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();
            if(!user.isEnabled())
            {
                return AuthenticationResponse.builder()
                        .isEnabled(user.isEnabled())
                        .token(identifier)
                        .name(user.getName())
                        .build();
            }
            throw new Exception("Token invalid");
        }

        @Override
        @GraphQLQuery(name = "ResendEmail")
        @PreAuthorize("hasAnyRole('ROLE_LEADER','ROLE_ADMIN')")
        public void ResendEmail(@GraphQLArgument(name = "identifier") String identifier)
        {
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();
            if(!user.isEnabled())
            {
                if(user.getEmail() != null || user.getEmail() != "")
                {
                    _emailSenderService.SendSetPasswortMail("oliver01@kabsi.at",user.getIdentifier(), user.getName());
                }
            }
        }
        @Override
        @GraphQLQuery(name = "GetAllUsers")
        @PreAuthorize("hasAnyRole('ROLE_LEADER','ROLE_ADMIN')")
        public List<UserResponse> GetAllUsers ()
        {
            List<UserResponse> response = UserEntitiesToResponses(_userRepository.findAll());
            return response;
        }

        @Override
        @GraphQLQuery(name = "GetUser")
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        public UserResponse GetUser (@GraphQLArgument(name = "identifier") String identifier)
        {
            UserEntity user = _userRepository.findByIdentifier(identifier).orElseThrow();

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
                //if(!user.getRole().contains(Role.USER))
                //{
                //    user.getRole().add(Role.USER);
                //}
                //if(!user.getRole().contains(Role.LEADER))
                //{
                //    user.getRole().add(Role.LEADER);
                //}
                //if(!user.getRole().contains(Role.ADMIN))
                //{
                //    user.getRole().add(Role.ADMIN);
                //}
                _userRepository.save(user);
            } catch (Exception ex)
            {
                UserEntity user = UserEntity.builder()
                        .identifier(UUID.randomUUID().toString())
                        .name("Oliver Stöckl")
                        .email("oliver01@kabsi.at")
                        .IsUserEnabled(true)
                        .password(_passwordEncoder.encode("Passwort"))
                        .role(Role.ADMIN)
                        .build();
                _userRepository.save(user);
            }

        }

        private String ExtractToken(DefaultGlobalContext < ServletWebRequest > env)
        {
            return env.getNativeRequest().getHeader(AUTHORIZATIONHEADER).substring(7);
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
                    .identifier(user.getIdentifier())
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
                    .role(user.getRole() != null ? user.getRole() : Role.USER)
                    .isEnabled(user.isEnabled());
            return builder.build();

        }
        private UserEntity UserRequestToEntity (UserRequest user)
        {
            return UserEntity.builder()
                    .identifier(user.getPassword())
                    .name(user.getName())
                    .email(user.getEmail() != null && !user.getEmail().equals("") ? user.getEmail() : null)
                    .telephoneNumber(user.getTelephoneNumber() != null && !user.getTelephoneNumber().equals("") ? user.getTelephoneNumber() : null)
                    .responsibleFor(user.getResponsibleFor())
                    .createdWorks(user.getCreatedWorks())
                    .createdVehicles(user.getCreatedVehicles())
                    .password(_passwordEncoder.encode(user.getPassword()))
                    .role(user.getRole() != null ? user.getRole() : Role.USER)
                    .build();
        }

        private List<UserResponse> UserEntitiesToResponses (List < UserEntity > users)
        {
            return users.stream().map(u -> UserResponse.builder()
                    .identifier(u.getIdentifier())
                    .name(u.getName())
                    .email(u.getEmail())
                    .telephoneNumber(u.getTelephoneNumber())
                    .responsibleForCount(_workRepository.countAllByResponsiblePerson(u))
                    .createdWorksCount(_workRepository.countAllByCreatedBy(u))
                    .createdVehiclesCount(_vehicleRepository.countAllByCreatedBy(u))
                    .updatedVehiclesCount(_vehicleRepository.countAllByUpdatedBy(u))
                    .updatedWorksCount(_workRepository.countAllByUpdatedBy(u))
                    .role(u.getRole() != null ? u.getRole() : Role.USER)
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
                UserEntity user = _userRepository.findByIdentifier(request.getResponsiblePersonIdentifier()).orElse(null);
                works.add(WorkEntity.builder()
                        .responsiblePerson(user)
                        .description(request.getDescription())
                        .priority(request.getPriority())
                        .identifier(UUID.randomUUID().toString())
                        .build());
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

