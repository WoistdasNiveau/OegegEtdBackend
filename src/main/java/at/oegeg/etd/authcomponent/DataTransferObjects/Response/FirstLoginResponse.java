package at.oegeg.etd.authcomponent.DataTransferObjects.Response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FirstLoginResponse
{
    private String token;
    private String password;
}
