package com.oegeg.etd.SaveComponent.Controller;

import com.oegeg.etd.SaveComponent.Repository.IVehicleRepository;
import com.oegeg.etd.SaveComponent.dto.Request.VehicleRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController("/oegegEtd/save")
@RequiredArgsConstructor
public class SaveController
{
    // == fields ==
    private final IVehicleRepository vehicleRepository;
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public String SaveVehicle(@RequestBody VehicleRequest request)
    {
        return "Saved";
    }
}
