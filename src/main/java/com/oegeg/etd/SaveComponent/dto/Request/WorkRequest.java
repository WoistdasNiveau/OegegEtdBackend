package com.oegeg.etd.SaveComponent.dto.Request;

import com.oegeg.etd.SaveComponent.Models.Enums.Priorities;

public record WorkRequest(String Description, String ResponsiblePerson, Priorities Priority)
{
    public WorkRequest
    {
        Priority = Priorities.NONE;
    }
}

//@Data
//public class WorkRequest
//{
//    private String Description;
//    private String ResponsiblePerson;
//    private Priorities Priority = Priorities.NONE;
//}
