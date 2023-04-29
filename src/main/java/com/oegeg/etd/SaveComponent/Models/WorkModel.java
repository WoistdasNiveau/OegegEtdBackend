package com.oegeg.etd.SaveComponent.Models;

import com.oegeg.etd.SaveComponent.Models.Enums.Priorities;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class WorkModel
{
    // == properties ==
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long ID;
    public String Description;
    public String ResponsiblePerson;
    public Priorities Priority = Priorities.NONE;
}
