package com.oegeg.etd.SaveComponent.dto.Request;

import com.oegeg.etd.SaveComponent.Models.Enums.Priorities;
import lombok.Builder;

import java.util.List;

@Builder
public record VehicleRequest (List<WorkRequest> Works, String Type, String Number, String Status, String Stand, Priorities Priority)
{
    //private final List<WorkRequest> Works;
    //private final String Type;
    //private final String Number;
    //private final String Status;
    //private final String Stand;
    //private final Priorities Priority;
}
