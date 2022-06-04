package com.example.securitydemo.controllers;

import com.example.securitydemo.entities.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("admin/api/v1/students")
public class AdminController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1L, "Pekka", "Ra"),
            new Student(2L, "Miguel", "Rafael"),
            new Student(3L, "Homo", "Rasse"),
            new Student(4L, "Simo", "Ranta")
    );

    // PreAuthorize: hasRole("ROLE_"), hasAnyRole("ROLE_"), hasAuthority("permission"), hasAnyAuthority("permission")
    // Instead of specifying the permissions inside the appsecconfig, we can do it on a method level inside the controller

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMIN_TRAINEE')")
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println(student + " registered successfully!");
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAnyAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentId") Long id) {
        System.out.println("Student with id: " + id + " deleted!");
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAnyAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId") Long id, @RequestBody Student student) {
        System.out.println("Updated student: " + id + ": " + student);
    }
}
