package at.oegeg.etd.authcomponent;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;

@EntityScan(basePackages = "at.oegeg.etd.sharedcomponent.Entities")
@SpringBootApplication
public class AuthComponentApplication
{

    public static void main(String[] args)
    {
        SpringApplication.run(AuthComponentApplication.class, args);
    }

}
