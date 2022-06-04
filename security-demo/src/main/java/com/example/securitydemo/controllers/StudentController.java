package com.example.securitydemo.controllers;

import com.example.securitydemo.entities.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1L, "Pekka", "Ra"),
            new Student(2L, "Miguel", "Rafael"),
            new Student(3L, "Homo", "Rasse"),
            new Student(4L, "Simo", "Ranta")
    );

    @GetMapping("{studentId}")
    public Student getStudent(@PathVariable("studentId") Long id) {
        return STUDENTS.stream()
                .filter(s -> s.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No such student"));
    }
}
