package com.oegeg.etd.SaveComponent.Models;

import com.oegeg.etd.SaveComponent.Models.Enums.Priorities;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Builder
public class WorkModel
{
    // == properties ==
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long ID;
    private String Description;
    private String ResponsiblePerson;
    private Priorities Priority = Priorities.NONE;
    @ManyToOne
    @JoinColumn(name = "VehicleID")
    private VehicleModel vehicleModel;
}
