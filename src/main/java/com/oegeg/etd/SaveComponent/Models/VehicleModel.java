package com.oegeg.etd.SaveComponent.Models;

import com.oegeg.etd.SaveComponent.Models.Enums.Priorities;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class VehicleModel
{
    // == properties ==
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public long Id;

    @OneToMany(mappedBy = "VehicleModel")
    public List<WorkModel> Works;
    public String Type;
    public String Number;
    public String Status;
    public String Stand;
    public Priorities Priority;
}
