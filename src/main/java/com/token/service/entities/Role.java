package com.token.service.entities;

import lombok.Data;

import javax.persistence.*;

@Entity
@Table(name = "tbl_role")
@Data
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    @Column(name = "id", nullable = false)
    private Long id;
    @Column(name = "name", nullable = false)
    private String name;
}