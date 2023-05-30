package at.oegeg.etd.authcomponent.Services.Interfaces;

import at.oegeg.etd.authcomponent.DataTransferObjects.Request.AuthenticationRequest;
import at.oegeg.etd.authcomponent.DataTransferObjects.Request.FirstLoginRequest;
import at.oegeg.etd.authcomponent.DataTransferObjects.Response.AuthenticationResponse;
import at.oegeg.etd.authcomponent.DataTransferObjects.Response.FirstLoginResponse;
import at.oegeg.etd.sharedcomponent.DataTransferObjects.Request.UserRequest;
import at.oegeg.etd.sharedcomponent.DataTransferObjects.Response.UserResponse;
import at.oegeg.etd.sharedcomponent.Entities.Enums.Role;
import io.leangen.graphql.annotations.GraphQLArgument;
import io.leangen.graphql.annotations.GraphQLRootContext;
import io.leangen.graphql.spqr.spring.autoconfigure.DefaultGlobalContext;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.List;

public interface IAuthService
{
    // == mutations ==
    void CreateUser(@GraphQLArgument(name = "user") UserRequest user);
    void DeleteUser(@GraphQLArgument(name = "nameEmailOrTelephoneNumber") String nameEmailOrTelephoneNumber);
    FirstLoginResponse SetPassword(@GraphQLArgument(name="firstLoginRequest") FirstLoginRequest firstLoginRequest);
    AuthenticationResponse SetRole (@GraphQLArgument(name = "identifier") String identifier,
                                    @GraphQLArgument(name = "role") Role role,
                                    @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env);

    //AuthenticationResponse RemoveRole(@GraphQLArgument(name = "emailOrTelephoneNumber") String emailOrTelephoneNumber,
    //                                  @GraphQLArgument(name = "role") Role role,
    //                                  @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env);
    void ChangeEmail(@GraphQLArgument(name = "oldEmail") String oldEmail,
                                       @GraphQLArgument(name = "newEmail") String newEmail,
                                       @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env);
    void ChangeTelephohneNumber(@GraphQLArgument(name = "oldTelephoneNumber") String oldTelephoneNumber,
                                                  @GraphQLArgument(name = "newTelephoneNumber") String newTelephoneNumber,
                                                  @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env);
    void ChangeName (@GraphQLArgument(name = "telephoneNumberOrEmail") String telephoneNumberOrEmail,
                     @GraphQLArgument(name = "newName") String newName,
                     @GraphQLRootContext DefaultGlobalContext < ServletWebRequest > env );
    AuthenticationResponse ChangePassword(@GraphQLArgument(name = "emailOrTelephoneNumber") String emailOrTelephoneNumber,
                                          @GraphQLArgument(name = "newPassword") String newPassword,
                                          @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env) throws Exception;

    AuthenticationResponse ChangeInitialPassword(@GraphQLArgument(name= "token") String token,
                                                 @GraphQLArgument(name = "password") String password) throws Exception;


    // == queries ==
    AuthenticationResponse Authenticate(@GraphQLArgument(name="AuthenticationRequest") AuthenticationRequest request) throws Exception;
    AuthenticationResponse ValidateToken(@GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env);
    void ResendEmail(@GraphQLArgument(name = "nameEmailOrTelephoneNumber") String nameEmailOrTelephoneNumber);
    List<UserResponse> GetAllUsers();
    UserResponse GetUser(@GraphQLArgument(name="nameEMailOrTelephoneNumber") String nameEmailOrTelephoneNumber);
    AuthenticationResponse ValidateFirstLoginToken(@GraphQLArgument(name = "token") String token) throws Exception;
}
