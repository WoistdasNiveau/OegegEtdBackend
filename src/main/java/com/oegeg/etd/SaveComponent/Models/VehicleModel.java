package com.oegeg.etd.SaveComponent.Models;

import com.oegeg.etd.SaveComponent.Models.Enums.Priorities;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Cascade;
import org.hibernate.annotations.CascadeType;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
public class VehicleModel
{
    // == properties ==
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long VehicleID;

    @OneToMany(mappedBy = "vehicleModel")
    @Cascade(CascadeType.ALL)
    private List<WorkModel> Works;
    private String Type;
    @Column(unique = true)
    private String Number;
    private String Status;
    private String Stand;
    private Priorities Priority;
}
