package com.oegeg.etd.SaveComponent.Repository;

import com.oegeg.etd.SaveComponent.Models.WorkModel;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IWorkRepository extends JpaRepository<WorkModel,Long>
{

}
