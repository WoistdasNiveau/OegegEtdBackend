package com.oegeg.etd.SaveComponent.Repository;

import com.oegeg.etd.SaveComponent.Models.VehicleModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IVehicleRepository extends JpaRepository<VehicleModel,Long>
{

}
