package at.oegeg.etd.authcomponent.DataTransferObjects.Request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FirstLoginRequest
{
    private String token;
    private String password;
}
