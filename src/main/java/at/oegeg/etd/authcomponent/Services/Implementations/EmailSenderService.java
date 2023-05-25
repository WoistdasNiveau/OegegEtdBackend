package at.oegeg.etd.authcomponent.Services.Implementations;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import static at.oegeg.etd.sharedcomponent.Constants.Constants.SENDERMAIL;

@Service
@RequiredArgsConstructor
public class EmailSenderService
{
    private final JavaMailSender _javaMailSender;

    public void SendSetPasswortMail(String email, String token, String name)
    {
        SimpleMailMessage message = new SimpleMailMessage();
        String body = "Dear " + name + "!" + System.lineSeparator() +
                "Your Group Leader has successfully created your OegegEtd Account. Please use following link to choose a " +
                "password and activate your account." + System.lineSeparator() +
                "http://localhost:8080/" + token.substring(7);

        message.setFrom(SENDERMAIL);
        message.setTo(email);
        message.setSubject("OegegEtd Account");
        message.setText(body);

        _javaMailSender.send(message);
    }
}
