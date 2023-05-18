package at.oegeg.etd.authcomponent.Services.Interfaces;

import at.oegeg.etd.authcomponent.DataTransferObjects.Request.AuthenticationRequest;
import at.oegeg.etd.authcomponent.DataTransferObjects.Response.AuthenticationResponse;
import at.oegeg.etd.sharedcomponent.DataTransferObjects.Request.UserRequest;
import at.oegeg.etd.sharedcomponent.Entities.Enums.Role;
import io.leangen.graphql.annotations.GraphQLArgument;
import io.leangen.graphql.annotations.GraphQLRootContext;
import io.leangen.graphql.spqr.spring.autoconfigure.DefaultGlobalContext;
import org.springframework.web.context.request.ServletWebRequest;

public interface IAuthService
{
    // == mutations ==
    void CreateUser(@GraphQLArgument(name = "user") UserRequest user);
    void SetRole(@GraphQLArgument(name = "emailOrTelefoneNumber") String emailOrTelefoneNumber, @GraphQLArgument(name = "role") Role role);
    AuthenticationResponse ChangeEmail(@GraphQLArgument(name = "oldEmail") String oldEmail,
                                       @GraphQLArgument(name = "newEmail") String newEmail,
                                       @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env);
    AuthenticationResponse ChangeTelephohneNumber(@GraphQLArgument(name = "oldTelephoneNumber") String oldTelephoneNumber,
                                                  @GraphQLArgument(name = "newTelephoneNumber") String newTelephoneNumber,
                                                  @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env);
    void ChangeName(@GraphQLArgument(name = "telephoneNumberOrEmail") String telephoneNumberOrEmail, @GraphQLArgument(name = "newName") String newName);
    AuthenticationResponse ChangePassword(@GraphQLArgument(name = "emailOrTelephoneNumber") String emailOrTelephoneNumber,
                                          @GraphQLArgument(name = "newPassword") String newPassword,
                                          @GraphQLRootContext DefaultGlobalContext<ServletWebRequest> env) throws Exception;


    // == queries ==
    AuthenticationResponse Authenticate(@GraphQLArgument(name="AuthenticationRequest") AuthenticationRequest request);
}