package at.oegeg.etd.authcomponent.DataTransferObjects.Response;

import at.oegeg.etd.sharedcomponent.Entities.Enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse
{
    private String token;
    private List<Role> roles;
}
