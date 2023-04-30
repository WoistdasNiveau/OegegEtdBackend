package com.oegeg.etd.SaveComponent.Services.Interfaces;

import com.oegeg.etd.SaveComponent.Models.VehicleModel;
import com.oegeg.etd.SaveComponent.dto.Request.VehicleRequest;

import java.util.List;


public interface IVehicleService
{
    void SaveVehicle(VehicleRequest vehicleRequest);
    List<VehicleModel> GetAlLVehicles();
}
