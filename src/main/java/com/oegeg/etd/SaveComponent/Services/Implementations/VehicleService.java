package com.oegeg.etd.SaveComponent.Services.Implementations;

import com.oegeg.etd.SaveComponent.Models.VehicleModel;
import com.oegeg.etd.SaveComponent.Models.WorkModel;
import com.oegeg.etd.SaveComponent.Repository.IVehicleRepository;
import com.oegeg.etd.SaveComponent.Services.Interfaces.IVehicleService;
import com.oegeg.etd.SaveComponent.dto.Request.VehicleRequest;
import com.oegeg.etd.SaveComponent.dto.Request.WorkRequest;
import io.leangen.graphql.annotations.GraphQLQuery;
import io.leangen.graphql.spqr.spring.annotations.GraphQLApi;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
@GraphQLApi
public class VehicleService implements IVehicleService
{
    // == fields ==
    private final IVehicleRepository _vehicleRepository;

    // == methods ==
    public void SaveVehicle(VehicleRequest vehicleRequest)
    {
        VehicleModel model = VehicleModel.builder()
                .Works(WorksToWorkModels(vehicleRequest.Works()))
                .Type(vehicleRequest.Type())
                .Number(vehicleRequest.Number())
                .Status(vehicleRequest.Status())
                .Stand(vehicleRequest.Stand())
                .Priority(vehicleRequest.Priority())
                .build();
        model.getWorks().stream().forEach(element -> element.setVehicleModel(model));
        _vehicleRepository.save(model);
    }

    @GraphQLQuery(name="GetAllVehicles")
    public List<VehicleModel> GetAlLVehicles()
    {
        return _vehicleRepository.findAll();
    }

    // == private methods ==
    private List<WorkModel> WorksToWorkModels(List<WorkRequest> request)
    {
        return request.stream().map(work -> WorkModel.builder()
                .Description(work.Description())
                .ResponsiblePerson(work.ResponsiblePerson())
                .Priority(work.Priority())
                .build()
        ).collect(Collectors.toList());
    }
}
