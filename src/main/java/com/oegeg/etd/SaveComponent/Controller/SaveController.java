package com.oegeg.etd.SaveComponent.Controller;

import com.oegeg.etd.SaveComponent.Services.Interfaces.IVehicleService;
import com.oegeg.etd.SaveComponent.dto.Request.VehicleRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/oegegEtd/save")
public class SaveController
{
    // == fields ==
    private final IVehicleService _vehicleService;
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public String SaveVehicle(@RequestBody VehicleRequest request)
    {
        try
        {
            _vehicleService.SaveVehicle(request);
            return "Saved";
        }
        catch (Exception ex)
        {
            return "Could not save vehicle";
        }
    }
}
